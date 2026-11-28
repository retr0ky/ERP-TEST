"""Regression checks for the 2026-11-28 audit fixes.

Run: python3 tests/test_fixes.py   (or: python3 -m pytest tests)
"""
import os
import pathlib
import sqlite3
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
os.environ["TURSO_URL"] = ""
os.environ["ERP_DB"] = str(HERE / "test_fixes.db")
os.environ["ERP_ADMIN_PASSWORD"] = "adminpass"
os.environ["ERP_MANAGER_PIN"] = "4321"
os.environ["ERP_DEBUG"] = "0"
sys.path.insert(0, str(HERE.parent))

DB = pathlib.Path(os.environ["ERP_DB"])
if DB.exists():
    DB.unlink()

import app as A                                    # noqa: E402

fails = []


def chk(cond, label, extra=""):
    print(("OK   " if cond else "FAIL ") + label + ((" | " + str(extra)[:160]) if extra else ""))
    if not cond:
        fails.append(label)


def raw():
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    return conn


def q1(sql, args=()):
    conn = raw()
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def run(sql, args=()):
    conn = raw()
    cur = conn.execute(sql, args)
    conn.commit()
    conn.close()
    return cur.lastrowid


def product(name, qty, price=1000.0):
    return run("INSERT INTO products (name, price, qty, active, n_search) VALUES (?, ?, ?, 1, ?)",
               (name, price, qty, name.casefold()))


run("INSERT INTO users (username, pass_hash, role) VALUES ('cash', 'x', 'cashier')")
ADMIN_UID = q1("SELECT id FROM users WHERE username = 'admin'")[0]
CASH_UID = q1("SELECT id FROM users WHERE username = 'cash'")[0]
PM = q1("SELECT key FROM payment_methods WHERE key = 'cash'")[0]


def client(admin=True, cart=None, sets=None, pays=None):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["csrf"] = "tok"
        s["authed"] = True
        s["uid"] = ADMIN_UID if admin else CASH_UID
        s["cart"] = cart or {}
        s["sets"] = sets or {}
        s["payments"] = pays or []
    return c


def post(c, url, data=None, csrf=True, headers=None):
    h = dict(headers or {})
    if csrf:
        h["X-CSRF-Token"] = "tok"
    return c.post(url, data=data or {}, headers=h)


def sell(cart=None, sets=None, amount=1000.0):
    c = client(cart=cart, sets=sets, pays=[{"method": PM, "amount": amount, "note": ""}])
    r = post(c, "/pos/checkout")
    loc = r.headers.get("Location", "")
    return int(loc.rsplit("/", 1)[1]) if "/sales/" in loc else None


# ------------------------------------------------------------ CSRF on admin routes
c = client()
r = post(c, "/accounts/new", {"username": "forged", "password": "forged1", "role": "admin"},
         csrf=False)
chk(r.status_code == 400 and q1("SELECT 1 FROM users WHERE username='forged'") is None,
    "admin POST without CSRF token is refused", r.status_code)
r = post(c, "/accounts/new", {"username": "legit", "password": "legit12", "role": "cashier"})
chk(q1("SELECT 1 FROM users WHERE username='legit'") is not None,
    "admin POST with the token still works")

# ------------------------------------------------------------ void keeps the sale
p1 = product("Void Widget", 5)
sid = sell(cart={str(p1): 2}, amount=2000.0)
chk(sid is not None and q1("SELECT qty FROM products WHERE id=?", (p1,))[0] == 3,
    "sale takes 2 from stock")
post(client(), f"/sales/{sid}/void")
row = q1("SELECT voided_at, voided_by FROM sales WHERE id=?", (sid,))
chk(row is not None and row["voided_at"] and row["voided_by"] == "admin",
    "voided sale is kept and marked", dict(row) if row else None)
chk(q1("SELECT qty FROM products WHERE id=?", (p1,))[0] == 5, "void returns the stock")
post(client(), f"/sales/{sid}/void")
chk(q1("SELECT qty FROM products WHERE id=?", (p1,))[0] == 5, "second void returns nothing more")
sid2 = sell(cart={str(p1): 1})
chk(sid2 == sid + 1, "next sale gets a new number, not the voided one's", (sid, sid2))
page = client().get(f"/sales/{sid}").get_data(as_text=True)
chk("VOIDED" in page and "Void sale</button>" not in page,
    "receipt shows VOIDED and no second Void button")
listing = client().get("/sales").get_data(as_text=True)
chk("VOIDED" in listing, "sales list marks the voided sale")
data = client().get("/sales?format=json").get_json()
chk(abs(data["total"] - 1000.0) < 0.01, "takings total skips voided sales", data["total"])

# number is never reused even after an old-style hard delete of the newest sale
run("DELETE FROM sales WHERE id=?", (sid2,))
sid3 = sell(cart={str(p1): 1})
chk(sid3 == sid2 + 1, "id of a deleted sale is not handed out again", (sid2, sid3))

# ------------------------------------------------------------ void of a set uses what was sold
pa, pb, pc = product("Set Part A", 10), product("Set Part B", 10), product("Set Part C", 10)
set_id = run("INSERT INTO sets (name, price) VALUES ('Test Bundle', 5000)")
run("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, 2)", (set_id, pa))
run("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, 1)", (set_id, pb))
sid = sell(sets={str(set_id): 1}, amount=5000.0)
chk(q1("SELECT qty FROM products WHERE id=?", (pa,))[0] == 8 and
    q1("SELECT qty FROM products WHERE id=?", (pb,))[0] == 9, "set sale takes its components")
# the admin edits the set afterwards: B removed, C added, A per-set changed
run("DELETE FROM set_products WHERE set_id=?", (set_id,))
run("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, 5)", (set_id, pa))
run("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, 1)", (set_id, pc))
run("UPDATE products SET active = 0 WHERE id = ?", (pb,))     # and soft-deletes B
post(client(), f"/sales/{sid}/void")
got = [q1("SELECT qty FROM products WHERE id=?", (x,))[0] for x in (pa, pb, pc)]
chk(got == [10, 10, 10], "set void returns exactly what was sold, not the edited set", got)


# ------------------------------------------------------------ stock adjust
pq = product("Adjust Widget", 5)
r = post(client(), f"/inventory/{pq}/adjust", {"direction": "in", "qty": "3", "reason": "delivery"})
chk(q1("SELECT qty FROM products WHERE id=?", (pq,))[0] == 8, "stock in adds")
log = q1("SELECT old_qty, new_qty, delta, reason FROM inventory_logs WHERE product_id=? "
         "ORDER BY id DESC", (pq,))
chk(tuple(log) == (5, 8, 3, "delivery"), "adjust is logged with the typed reason", tuple(log))
# a sale lands after the form loaded (stock 8 -> 6); the adjust must not overwrite it
run("UPDATE products SET qty = qty - 2 WHERE id = ?", (pq,))
post(client(), f"/inventory/{pq}/adjust", {"direction": "in", "qty": "1"})
chk(q1("SELECT qty FROM products WHERE id=?", (pq,))[0] == 7, "adjust is relative (6 + 1 = 7)")
r = post(client(), f"/inventory/{pq}/adjust", {"direction": "out", "qty": "50"})
chk(q1("SELECT qty FROM products WHERE id=?", (pq,))[0] == 7, "cannot take out more than stock")
cash = client(admin=False)
r = post(cash, f"/inventory/{pq}/adjust", {"direction": "out", "qty": "2"})
chk(r.status_code == 401 and q1("SELECT qty FROM products WHERE id=?", (pq,))[0] == 7,
    "cashier stock-out asks for the PIN")
r = post(cash, f"/inventory/{pq}/adjust", {"direction": "out", "qty": "2", "admin_pin": "4321"})
chk(q1("SELECT qty FROM products WHERE id=?", (pq,))[0] == 5,
    "correct PIN applies the stock-out on the same submit")

# ------------------------------------------------------------ manager PIN
pz = product("Pin Widget", 1)
cash = client(admin=False)
r = post(cash, f"/inventory/{pz}/delete", {"admin_pin": "adminpass"})
chk(r.status_code == 401, "admin login password is not the manager PIN when ERP_MANAGER_PIN is set")
page = r.get_data(as_text=True)
chk("adminpass" not in page and "Wrong PIN" in page, "wrong PIN is reported and not echoed back")
r = cash.post(f"/inventory/{pz}/delete?admin_pin=4321", headers={"X-CSRF-Token": "tok"})
chk(r.status_code == 401, "PIN in the query string is ignored")
for _ in range(A.LOGIN_MAX_FAILS):
    post(cash, f"/inventory/{pz}/delete", {"admin_pin": "0000"})
r = post(cash, f"/inventory/{pz}/delete", {"admin_pin": "4321"})
chk(r.status_code == 401 and "Too many wrong PINs" in r.get_data(as_text=True),
    "PIN guessing is locked out, even the right PIN waits")
run("DELETE FROM login_throttle")

# ------------------------------------------------------------ login lockout
anon = A.app.test_client()
anon.get("/login")
with anon.session_transaction() as s_:
    tok = s_.get("csrf", "")
for i in range(A.LOGIN_MAX_FAILS):
    anon.post("/login", data={"username": "admin", "password": "nope", "csrf": tok},
              headers={"X-Forwarded-For": f"10.0.0.{i}"})
r = anon.post("/login", data={"username": "admin", "password": "nope", "csrf": tok},
              headers={"X-Forwarded-For": "10.9.9.9"})
chk(r.status_code == 429, "spoofed X-Forwarded-For does not reset the login lockout", r.status_code)
chk(q1("SELECT COUNT(*) FROM login_throttle")[0] >= 1, "lockout state lives in the database")
run("DELETE FROM login_throttle")


# ------------------------------------------------------------ card surcharge is charged
run("UPDATE payment_methods SET commission_percent = 2, commission_mode = 'SURCHARGE' WHERE key = 'card'")
ps = product("Surcharge Widget", 3, price=100000.0)
c = client(cart={str(ps): 1})
d = post(c, "/pos/api/pay/exact", {"method": "card"}).get_json()
chk(d["ok"] and abs(d["surcharge"] - 2000) < 0.01 and abs(d["total"] - 102000) < 0.01
    and d["can_complete"], "card +2%: total 102,000, surcharge shown, sale completes",
    {k: d.get(k) for k in ("surcharge", "total", "paid", "balance")})
page = c.get("/pos?open=1").get_data(as_text=True)
chk('"card": 2' in page.replace(".0", "") and "t-fee" in page, "POS page knows the surcharge rate")
r = post(c, "/pos/checkout")
sid = int(r.headers["Location"].rsplit("/", 1)[1])
row = q1("SELECT total, paid, change FROM sales WHERE id=?", (sid,))
chk(tuple(row) == (102000.0, 102000.0, 0.0), "sale stores the surcharged total", tuple(row))
rc = client().get(f"/sales/{sid}").get_data(as_text=True)
chk("Customer surcharge" in rc and "100,000₮" in rc, "receipt: goods 100,000 + surcharge line")
run("UPDATE payment_methods SET commission_percent = 0, commission_mode = 'ABSORBED' WHERE key = 'card'")
rc = client().get(f"/sales/{sid}").get_data(as_text=True)
chk("Customer surcharge" in rc, "receipt keeps the surcharge after the rate is changed")


# ------------------------------------------------------------ foreign keys + purge guard
c = client()
post(c, "/inventory/new", {"name": "Audit Widget", "price": "10", "qty": "4", "sku": "AUD-1"})
pn = q1("SELECT id FROM products WHERE sku = 'AUD-1'")[0]
log = q1("SELECT old_qty, new_qty, delta, reason FROM inventory_logs WHERE product_id=?", (pn,))
chk(log is not None and tuple(log) == (0, 4, 4, "new product"), "opening stock is logged",
    tuple(log) if log else None)
post(c, f"/inventory/{pn}/edit", {"name": "Audit Widget", "price": "10", "qty": "9", "sku": "AUD-1"})
log = q1("SELECT old_qty, new_qty, delta, reason FROM inventory_logs WHERE product_id=? "
         "ORDER BY id DESC", (pn,))
chk(tuple(log) == (4, 9, 5, "edited on product form"), "editing qty on the form is logged",
    tuple(log))
n = q1("SELECT COUNT(*) FROM inventory_logs WHERE product_id=?", (pn,))[0]
post(c, f"/inventory/{pn}/edit", {"name": "Audit Widget 2", "price": "10", "qty": "9", "sku": "AUD-1"})
chk(q1("SELECT COUNT(*) FROM inventory_logs WHERE product_id=?", (pn,))[0] == n,
    "edit without a qty change writes no stock log")

sid_set = run("INSERT INTO sets (name) VALUES ('Guard Set')")
run("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, 1)", (sid_set, pn))
post(c, f"/inventory/{pn}/delete")
r = post(c, f"/inventory/{pn}/purge")
chk(q1("SELECT 1 FROM products WHERE id=?", (pn,)) is not None,
    "purge refused while the product is in a set")
run("DELETE FROM set_products WHERE set_id=?", (sid_set,))
sid = sell(cart={str(p1): 1})
item = q1("SELECT id FROM sale_items WHERE sale_id=?", (sid,))[0]
post(c, f"/inventory/{p1}/delete")
post(c, f"/inventory/{p1}/purge")
chk(q1("SELECT product_id FROM sale_items WHERE id=?", (item,))[0] is None,
    "purge: past sale lines keep their name, product_id becomes NULL (foreign keys on)")
chk(A.connect().execute("PRAGMA foreign_keys").fetchone()[0] == 1, "connections enable foreign keys")


# ------------------------------------------------------------ shop-local time, debug off
from datetime import datetime, timedelta, timezone
ub = datetime.now(timezone(timedelta(hours=8)))       # Ulaanbaatar has no DST
p2 = product("Clock Widget", 2)
sid = sell(cart={str(p2): 1})
stamp = q1("SELECT created_at FROM sales WHERE id=?", (sid,))[0]
got = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone(timedelta(hours=8)))
chk(abs((got - ub).total_seconds()) < 120, "sale time is Ulaanbaatar time", (stamp, ub))
lg = q1("SELECT created_at FROM inventory_logs WHERE sale_id=?", (sid,))[0]
chk(lg == stamp, "its stock log carries the same timestamp", (lg, stamp))
chk(A.DEBUG_MODE is False, "debug mode is off unless ERP_DEBUG=1")


# ------------------------------------------------------------ money input
c = client()
for bad in ("nan", "inf", "1e9", "-5", "1.2.3"):
    post(c, "/inventory/new", {"name": f"Bad {bad}", "price": bad, "qty": "1"})
    chk(q1("SELECT 1 FROM products WHERE name=?", (f"Bad {bad}",)) is None,
        f"product price '{bad}' is refused")
post(c, "/inventory/new", {"name": "Good Price", "price": "1,900,000", "cost": "12.5", "qty": "1"})
row = q1("SELECT price, cost FROM products WHERE name='Good Price'")
chk(row is not None and tuple(row) == (1900000.0, 12.5), "1,900,000 and 12.5 are accepted",
    tuple(row) if row else None)


# ------------------------------------------------------------ sales paging
A.SALES_PAGE = 3
c = client()
all_ = q1("SELECT COUNT(*) AS n, SUM(CASE WHEN voided_at IS NULL THEN total END) AS t FROM sales")
d = c.get("/sales?format=json").get_json()
chk(len(d["rows"]) == 3 and d["count"] == all_["n"] and d["pages"] > 1,
    "sales list is paged, count covers every sale", (len(d["rows"]), d["count"], d["pages"]))
chk(abs(d["total"] - all_["t"]) < 0.01, "takings total covers every page, not just this one")
d2 = c.get(f"/sales?format=json&page={d['pages']}").get_json()
chk(d2["page"] == d["pages"] and d2["rows"] and d2["rows"][0]["id"] < d["rows"][-1]["id"],
    "last page holds the oldest sales")
html = c.get("/sales?page=2").get_data(as_text=True)
chk("page 2 of" in html and "Older" in html and "Newer" in html, "pager links render")
A.SALES_PAGE = 100


# ------------------------------------------------------------ malformed held carts
c = client()
h1 = run("INSERT INTO held_carts (label, data) VALUES ('list blob', '[1, 2]')")
r = post(c, f"/pos/hold/{h1}/resume")
chk(r.status_code == 302, "held cart that is a JSON list does not crash resume", r.status_code)
h2 = run("""INSERT INTO held_carts (label, data) VALUES ('bad pays',
         '{"v": 1, "cart": {}, "sets": {}, "payments": [{"method": "cash"}, "x",
           {"method": "cash", "amount": "nan"}, {"method": "cash", "amount": 500}]}')""")
post(c, f"/pos/hold/{h2}/resume")
with c.session_transaction() as s_:
    pays = s_.get("payments")
chk(pays == [{"method": "cash", "amount": 500.0, "note": ""}],
    "only well-formed payment lines survive a resume", pays)
chk(c.get("/pos").status_code == 200, "POS still renders after resuming it")


# --------------------------------------------------------------------------- done
print("\nFAILS:", fails or "none")
sys.exit(1 if fails else 0)
