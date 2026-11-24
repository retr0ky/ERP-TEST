"""Checkout, stock guard, admin PIN, login throttle, security headers, held carts.

Run: python3 tests/test_checkout.py
"""
import os
import pathlib
import sqlite3
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
os.environ["TURSO_URL"] = ""
os.environ["ERP_DB"] = str(HERE / "test_checkout.db")
os.environ["ERP_PASSWORD"] = "shoppass"
os.environ["ERP_ADMIN_PASSWORD"] = "pinpass"
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
    return sqlite3.connect(str(DB))


# ------------------------------------------------------------------ fixtures
conn = raw()
conn.execute("INSERT INTO products (name, price, qty, active) VALUES (?, ?, ?, 1)",
             ("Race Widget", 200000.0, 1))
conn.commit()
pid = conn.execute("SELECT id FROM products WHERE name = 'Race Widget'").fetchone()[0]
pm = conn.execute("SELECT key FROM payment_methods WHERE active = 1 LIMIT 1").fetchone()[0]
conn.close()


def client_for(cart=None, pays=None, admin=True):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["csrf"] = "tok"
        s["authed"] = True
        s["cart"] = {str(pid): 1} if cart is None else cart
        s["sets"] = {}
        s["payments"] = [{"method": pm, "amount": 200000.0, "note": ""}] if pays is None else pays
        if admin:
            s["admin_until"] = time.time() + 600
    return c


def post(c, url, data=None, headers=None):
    h = dict(headers or {})
    h["X-CSRF-Token"] = "tok"
    return c.post(url, data=data or {}, headers=h)


# --------------------------------------------------------- 1. happy path sale
c = client_for()
r = post(c, "/pos/checkout")
chk(r.status_code == 302 and "/sales/" in r.headers.get("Location", ""),
    "checkout redirects to the receipt", r.headers.get("Location"))
conn = raw()
sale = conn.execute("SELECT id, total, paid, change, item_count FROM sales ORDER BY id DESC").fetchone()
qty = conn.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()[0]
logs = conn.execute("SELECT old_qty, new_qty, delta, reason, sale_id FROM inventory_logs "
                    "WHERE product_id = ?", (pid,)).fetchall()
sales = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0]
items = conn.execute("SELECT COUNT(*) FROM sale_items WHERE sale_id = ?", (sale[0],)).fetchone()[0]
pays = conn.execute("SELECT COUNT(*) FROM payments WHERE sale_id = ?", (sale[0],)).fetchone()[0]
conn.close()
chk(sale == (sale[0], 200000.0, 200000.0, 0.0, 1), "sale row carries the right money", sale)
chk(qty == 0, "stock decremented once", qty)
chk(items == 1 and pays == 1, "one sale_item and one payment written", (items, pays))
chk(logs == [(1, 0, -1, "sale", sale[0])], "inventory log written inside the same transaction", logs)

# --------------------------------------------------- 2. the race for the last unit
conn = raw(); conn.execute("UPDATE products SET qty = 1 WHERE id = ?", (pid,)); conn.commit(); conn.close()
c1, c2 = client_for(), client_for()
r1, r2 = post(c1, "/pos/checkout"), post(c2, "/pos/checkout")
won = [r for r in (r1, r2) if r.status_code == 302 and "/sales/" in r.headers.get("Location", "")]
lost = [r for r in (r1, r2) if "/sales/" not in r.headers.get("Location", "")]
conn = raw()
qty = conn.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()[0]
sales = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0]
conn.close()
chk(len(won) == 1 and len(lost) == 1, "one checkout wins the last unit", (r1.status_code, r2.status_code))
chk(qty == 0, "stock never goes negative", qty)
chk(sales == 2, "only as many sales as winners", sales)

# --------------------------------------- 3. guard aborts without a half-written sale
conn = raw()
c = A.DB(conn)
before = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0]
try:
    c.script([("INSERT INTO sales (id, ref, total, paid, change, item_count, vat_amount) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)", (999999, "SALE-999999", 1, 1, 0, 1, 0)),
              ("WITH need(pid, qty) AS (VALUES (?, ?)) "
               "INSERT INTO stock_guards (id) SELECT 1 FROM need "
               "WHERE COALESCE((SELECT qty FROM products WHERE id = need.pid), -1) < need.qty",
               (pid, 5)),
              ("UPDATE products SET qty = qty - ? WHERE id = ?", (5, pid))])
    aborted = False
except sqlite3.IntegrityError:
    aborted = True
after = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0]
qty = conn.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()[0]
conn.close()
chk(aborted, "stock guard raises IntegrityError")
chk(after == before, "the sale INSERT before the guard is rolled back", (before, after))
chk(qty == 0, "the UPDATE after the guard never landed", qty)

# ------------------------------------------- 4. nothing is formatted into SQL text
c = client_for(cart={str(pid): "1 OR 1=1"},
               pays=[{"method": pm, "amount": 200000.0, "note": ""}])
r = post(c, "/pos/checkout")
conn = raw()
qty = conn.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()[0]
conn.close()
chk(r.status_code in (302, 200) and qty == 0,
    "junk qty in the session cart is coerced, not interpolated", (r.status_code, qty))

# --------------------------------------------------- 5. amount parsing is strict
chk(A.parse_amount("1.2.3") is None, "parse_amount rejects '1.2.3'")
chk(A.parse_amount("1,900,000") == 1900000.0, "parse_amount accepts grouped digits")
chk(A.parse_amount(".5") == 0.5, "parse_amount accepts '.5'")

# ---------------------------------------------- 6. login cannot be brute-forced
c = A.app.test_client()
with c.session_transaction() as s0:
    s0["csrf"] = "tok"
codes = [c.post("/login", data={"password": "wrong%d" % i}, headers={"X-CSRF-Token": "tok"}).status_code
         for i in range(8)]
chk(429 in codes, "login throttles after repeated failures", codes)

# ------------------------------------------------------- 7. security headers exist
r = A.app.test_client().get("/pos")
h = r.headers
chk("Content-Security-Policy" in h and "frame-ancestors 'none'" in h["Content-Security-Policy"],
    "CSP shipped", h.get("Content-Security-Policy"))
chk(h.get("X-Frame-Options") == "DENY", "X-Frame-Options DENY")
chk(h.get("X-Content-Type-Options") == "nosniff", "X-Content-Type-Options nosniff")
chk(h.get("Referrer-Policy") == "strict-origin-when-cross-origin", "Referrer-Policy shipped")

# --------------------------------------------- 8. admin gate answers API callers
c = A.app.test_client()
with c.session_transaction() as s:
    s["csrf"] = "tok"
    s["authed"] = True
    s.pop("admin_until", None)
r = post(c, f"/inventory/{pid}/delete", headers={"X-FX": "1"})
body = r.get_json() or {}
chk(r.status_code == 401 and body.get("code") == "ADMIN_REQUIRED",
    "admin gate returns JSON to fetch callers", (r.status_code, body))
r = post(c, f"/inventory/{pid}/delete", data={"admin_pin": "pinpass"}, headers={"X-FX": "1"})
chk(r.status_code in (200, 302), "a correct PIN lets the action through", r.status_code)

# ---------------------------------------------------- 9. held carts are versioned
conn = raw()
conn.execute("INSERT INTO held_carts (label, data) VALUES (?, ?)",
             ("Future cart", '{"v": 99, "cart": {"1": 1}, "sets": {}, "payments": []}'))
conn.commit()
hid = conn.execute("SELECT id FROM held_carts WHERE label = 'Future cart'").fetchone()[0]
conn.close()
c = client_for(cart={})
r = post(c, f"/pos/hold/{hid}/resume")
with c.session_transaction() as s:
    chk(s.get("cart") == {}, "resume refuses a held cart written by another build", s.get("cart"))
conn = raw()
chk(conn.execute("SELECT COUNT(*) FROM held_carts WHERE id = ?", (hid,)).fetchone()[0] == 1,
    "the refused blob is left in place")
conn.close()

# --------------------------------------------- 10. csrf failure is JSON for fetch
c = A.app.test_client()
with c.session_transaction() as s:
    s["csrf"] = "tok"
    s["authed"] = True
r = c.post("/pos/clear", data={}, headers={"X-FX": "1", "X-CSRF-Token": "nope"})
chk(r.status_code == 400 and (r.get_json() or {}).get("error"),
    "csrf failure answers fetch with JSON", (r.status_code, r.get_data(as_text=True)[:80]))

print()
print("FAILED: " + ", ".join(fails) if fails else "all checkout checks pass")
sys.exit(1 if fails else 0)
