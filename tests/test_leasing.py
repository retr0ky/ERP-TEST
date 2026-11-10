import re, sqlite3, sys
sys.path.insert(0, "/home/inthearmsofdevastation/Desktop/ERP")
import app as A

DB = A.DB_PATH
fails = []
def chk(cond, label, extra=""):
    print(("OK   " if cond else "FAIL ") + label + ((" | " + str(extra)) if extra else ""))
    if not cond:
        fails.append(label)

c = A.app.test_client()

# 1. pick a product with stock (pay modal only renders when the cart is not empty)
conn = A.connect()
prod = conn.execute("SELECT * FROM products WHERE active=1 AND qty>=2 ORDER BY id LIMIT 1").fetchone()
conn.close()
chk(prod is not None, "found a stocked product")
c.post(f"/pos/add/{prod['id']}")

# 2. leasing option + note field in POS markup
html = c.get("/pos?open=1").get_data(as_text=True)
chk("Leasing" in html, "Leasing option rendered")
chk('data-note="1"' in html, "leasing option carries data-note")
chk('id="pay-note"' in html and 'name="note"' in html, "note input present in pay form")

# 3. leasing without note blocked (api + form paths)
d = c.post("/pos/api/pay", data={"method": "leasing", "amount": "500"},
           headers={"X-Requested-With": "xhr"}).get_json()
chk(d["ok"] is False and "note" in d["error"], "API blocks leasing without note", d.get("error"))
d = c.post("/pos/pay", data={"method": "leasing", "amount": "500"}, follow_redirects=True)
chk("needs a note" in d.get_data(as_text=True), "form path blocks leasing without note")

# 4. leasing with note accepted
d = c.post("/pos/api/pay", data={"method": "leasing", "amount": "500",
                                "note": "Udval Leasing app"},
           headers={"X-Requested-With": "xhr"}).get_json()
chk(d["ok"] and d["lines"][0]["note"] == "Udval Leasing app", "leasing line stores note", d["lines"])
chk(d["lines"][0]["needs_note"] is False, "needs_note false once note typed")

# 5. note shown in payment lines table (server render + api payload)
chk("Udval Leasing app" in c.get("/pos?open=1").get_data(as_text=True), "note rendered on POS pay line")

# 6. can_complete gating: still due -> false, then pay remaining with cash
chk(d["can_complete"] is False, "can_complete false while balance due")
d = c.post("/pos/api/pay/exact", data={"method": "cash"},
           headers={"X-Requested-With": "xhr"}).get_json()
chk(d["ok"] and d["can_complete"] is True, "can_complete true once fully paid")

# 7. checkout persists the note
r = c.post("/pos/checkout", data={"customer_phone": "99110011", "customer_note": "leasing test"},
           follow_redirects=True)
page = r.get_data(as_text=True)
m = re.search(r"/sales/(\d+)", r.get_data(as_text=True))
conn = A.connect()
sale = conn.execute("SELECT * FROM sales WHERE id=?", (int(m.group(1)),)).fetchone()
pays = conn.execute("SELECT * FROM payments WHERE sale_id=? ORDER BY id", (sale["id"],)).fetchall()
chk(any(p["method"] == "leasing" and p["note"] == "Udval Leasing app" for p in pays),
    "payments.note persisted for leasing")

# 8. receipt + sales list show the note
rec = c.get(f"/sales/{sale['id']}").get_data(as_text=True)
chk("Udval Leasing app" in rec, "receipt shows leasing note")
sales_html = c.get("/sales").get_data(as_text=True)
chk("Udval Leasing app" in sales_html, "sales list split shows leasing note")
srch = c.get("/sales?q=Udval").get_data(as_text=True)
chk(f"/sales/{sale['id']}" in srch, "sales search matches payment note")

# 9. void restores stock and removes the test sale
c.post(f"/sales/{sale['id']}/void", follow_redirects=True)
conn2 = A.connect()
chk(conn2.execute("SELECT COUNT(*) n FROM sales WHERE id=?", (sale["id"],)).fetchone()["n"] == 0,
    "test sale voided")
now = conn2.execute("SELECT qty FROM products WHERE id=?", (prod["id"],)).fetchone()["qty"]
conn2.close()
chk(now >= prod["qty"], "stock restored after void", f"{prod['qty']} -> {now}")

print("\nFAILS:", fails or "none")
sys.exit(1 if fails else 0)
