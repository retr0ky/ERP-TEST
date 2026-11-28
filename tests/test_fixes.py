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


# --------------------------------------------------------------------------- done
print("\nFAILS:", fails or "none")
sys.exit(1 if fails else 0)
