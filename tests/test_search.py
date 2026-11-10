import json, sqlite3, sys
sys.path.insert(0, "/home/inthearmsofdevastation/Desktop/ERP")
import app as A

fails = []
def chk(cond, label, extra=""):
    print(("OK   " if cond else "FAIL ") + label + ((" | " + str(extra)[:150]) if extra else ""))
    if not cond:
        fails.append(label)

def search(q, **kw):
    r = A.app.test_client().get("/pos/search", query_string=dict(q=q, **kw))
    return r.get_json()

c = A.app.test_client()

# --- POS autocomplete: multi-word, any order, case-insensitive (incl. Cyrillic)
hits = [p["name"] for p in search("rtx 5060")]
chk(any("RTX5060" in h for h in hits), "POS search: 'rtx 5060' finds ASUS DUAL RTX5060", hits)
hits = [p["name"] for p in search("5060 rtx")]
chk(any("RTX5060" in h for h in hits), "POS search: words in reverse order still match", hits)
hits = [p["name"] for p in search("ШИРЭЭ")]
chk(any("Ширээ" in h for h in hits), "POS search: uppercase Cyrillic matches (was 0 before)", hits)
hits = [p["name"] for p in search("хар")]
chk(any("Хар" in h for h in hits), "POS search: Cyrillic lowercase finds uppercase in DB", hits)
hits = [p["name"] for p in search("ХАР")]
chk(any("Хар" in h for h in hits), "POS search: Cyrillic uppercase finds uppercase in DB", hits)
chk(search("gaming sandal") and len(search("gaming sandal")) == 1,
    "POS search: two words AND-ed", [p['name'] for p in search("gaming sandal")])
chk(len(search("%")) == 0, "POS search: bare % no longer matches everything")
chk(len(search("_")) == 0, "POS search: bare _ no longer matches everything")
sku = A.connect().execute(
    "SELECT sku,name FROM products WHERE IFNULL(sku,'')<>'' LIMIT 1").fetchone()
chk(any(p["name"] == sku[1] for p in search(sku[0])), "POS search: exact SKU matches", sku)
bar = A.connect().execute(
    "SELECT barcode,name FROM products WHERE IFNULL(barcode,'')<>'' LIMIT 1").fetchone()
chk(any(p["name"] == bar[1] for p in search(bar[0])), "POS search: exact barcode matches", bar)
chk(all(p["amount"] > 0 for p in search("rtx")), "POS search payload carries amount for the browse grid")

# --- POS page + browse sets (server-rendered)
html = c.get("/pos?browse=1&q=gaming sandal").get_data(as_text=True)
chk("Gaming sandal" in html, "POS browse page: multi-word product hit")
conn = A.connect()
s = conn.execute("SELECT * FROM sets WHERE active=1 LIMIT 1").fetchone()
words = (s["name"] or "").split()
if len(words) >= 2:
    rev = " ".join(reversed(words))
    h2 = c.get("/pos?browse=1&q=" + rev).get_data(as_text=True)
    chk(s["name"] in h2, "POS browse page: set found with words reordered", f"{rev} -> {s['name']}")

# --- Inventory search
h = c.get("/inventory?tab=products&q=5060 rtx").get_data(as_text=True)
chk("RTX5060" in h, "Inventory: multi-word search")
h = c.get("/inventory?tab=products&q=ШИРЭЭ").get_data(as_text=True)
chk("Ширээ" in h, "Inventory: uppercase Cyrillic search")
h = c.get("/inventory?tab=products&q=intel").get_data(as_text=True)
chk("Intel Core i5" in h, "Inventory: brand substring search")
h = c.get("/inventory?tab=products&q=%").get_data(as_text=True)
chk(h.count("<tr>") < 20, "Inventory: bare % is literal, not a wildcard")

# --- Barcode / SKU scan (case-folded exact)
r = c.post("/pos/scan", data={"barcode": bar[0]}, follow_redirects=True)
chk("Scanned" in r.get_data(as_text=True), "Scan: exact barcode adds to cart", bar)
r = c.post("/pos/scan", data={"barcode": sku[0].upper()}, follow_redirects=True)
chk("Scanned" in r.get_data(as_text=True), "Scan: SKU matches regardless of case", sku)
r = c.post("/pos/scan", data={"barcode": "zzz-nope"}, follow_redirects=True)
chk("no product matches" in r.get_data(as_text=True), "Scan: miss reports clearly")

# --- Sales search: ref, phone, payment note, item name
sale = conn.execute("SELECT * FROM sales ORDER BY id DESC LIMIT 1").fetchone()
item = conn.execute("SELECT name FROM sale_items WHERE sale_id=? LIMIT 1", (sale["id"],)).fetchone()
def sales_json(q):
    d = c.get("/sales", query_string={"q": q, "format": "json"}).get_json()
    return d["rows"]
chk(any(r["id"] == sale["id"] for r in sales_json(sale["ref"])), "Sales: ref search")
iname = item["name"].split()[-1]
chk(any(r["id"] == sale["id"] for r in sales_json(iname)), "Sales: item name search", f"{iname} -> {sale['ref']}")
chk(len(sales_json("%")) == 0, "Sales: bare % is literal")
chk(any(r["id"] == sale["id"] for r in sales_json(sale["ref"].lower())), "Sales: ref search is case-insensitive")
total = conn.execute("SELECT COUNT(*) n FROM sales").fetchone()["n"]
chk(len(sales_json("")) == total, "Sales: empty query returns all")
conn.close()

print("\nFAILS:", fails or "none")
sys.exit(1 if fails else 0)
