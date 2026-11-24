"""Accounts, roles (admin / cashier), manager-PIN escalation, last-admin guard."""
import os
import sqlite3
import sys
from pathlib import Path

os.environ["TURSO_URL"] = ""
os.environ["ERP_DB"] = str(Path(__file__).resolve().parent / "test_accounts.db")
os.environ["ERP_ADMIN_PASSWORD"] = "pinpass"
for suffix in ("", "-wal", "-shm"):
    p = Path(os.environ["ERP_DB"] + suffix)
    if p.exists():
        p.unlink()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app as A

fails = []
def chk(cond, label, extra=""):
    print(("OK   " if cond else "FAIL ") + label + ((" | " + str(extra)[:150]) if extra else ""))
    if not cond:
        fails.append(label)


def raw():
    conn = sqlite3.connect(os.environ["ERP_DB"])
    conn.row_factory = sqlite3.Row
    return conn


def login(username, password):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["csrf"] = "tok"
    r = c.post("/login", data={"username": username, "password": password, "csrf": "tok"})
    return c, r


def post(c, url, data=None, headers=None):
    with c.session_transaction() as s:      # login rotates the csrf token
        t = s.get("csrf", "tok")
    h = dict(headers or {})
    h["X-CSRF-Token"] = t
    d = dict(data or {})
    d.setdefault("csrf", t)
    return c.post(url, data=d, headers=h)


def user_row(username):
    conn = raw()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


# --------------------------------------------------------- 1. login is per account
admin, r = login("admin", "pinpass")
chk(r.status_code == 302, "admin logs in with username + password")
with admin.session_transaction() as s:
    chk(s.get("role") == "admin", "session carries the role")
_, r = login("admin", "nope")
chk(r.status_code == 200, "wrong password does not log in")
_, r = login("nosuchuser", "pinpass")
chk(r.status_code == 200, "unknown username does not log in")

# ---------------------------------------------------------- 2. admin makes a cashier
r = post(admin, "/accounts/new", {"username": "cash1", "password": "cashpass", "role": "cashier"})
chk(r.status_code == 302, "admin creates an account")
row = user_row("cash1")
chk(row is not None and row["role"] == "cashier", "cashier exists in users table")
r = post(admin, "/accounts/new", {"username": "BAD USER!", "password": "x12345", "role": "cashier"})
chk(user_row("BAD USER!") is None, "junk username is rejected")
chk(len(user_row("admin")["pass_hash"]) > 20 and "pinpass" not in user_row("admin")["pass_hash"],
    "passwords are stored hashed")

cash, r = login("cash1", "cashpass")
chk(r.status_code == 302, "cashier logs in")

# ------------------------------------------------- 3. cashier may sell / restock / add
chk(cash.get("/pos").status_code == 200, "cashier can open POS")
chk(cash.get("/sales").status_code == 200, "cashier can view sales")
r = post(cash, "/inventory/new", {"name": "Cashier Widget", "cost": "1000", "price": "1500", "qty": "3"})
chk(r.status_code == 302, "cashier can add a fresh product")
conn = raw()
pid = conn.execute("SELECT id FROM products WHERE name = 'Cashier Widget'").fetchone()[0]
conn.close()
r = post(cash, f"/inventory/{pid}/adjust", {"direction": "in", "qty": "2"})
conn = raw()
qty = conn.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()[0]
conn.close()
chk(r.status_code == 302 and qty == 5, "cashier can stock in (restock)", qty)
r = post(cash, f"/pos/add/{pid}")
chk(r.status_code in (200, 302), "cashier can sell (add to cart)")

# ------------------------------------------------------- 4. cashier may not destroy
r = post(cash, f"/inventory/{pid}/delete", headers={"X-FX": "1"})
chk(r.status_code == 401 and (r.get_json() or {}).get("code") == "ADMIN_REQUIRED",
    "cashier cannot delete a product", r.status_code)
chk(cash.get(f"/inventory/{pid}/edit").status_code == 401, "cashier never sees the edit form")
chk(cash.get("/accounts").status_code == 401, "cashier cannot open Accounts")
chk(cash.get("/inventory/sets/new").status_code == 401, "cashier cannot open the set form")
r = post(cash, f"/inventory/{pid}/adjust", {"direction": "out", "qty": "1"}, headers={"X-FX": "1"})
chk(r.status_code == 401, "cashier cannot stock out", r.status_code)
r = post(cash, "/sales/1/void", headers={"X-FX": "1"})
chk(r.status_code == 401, "cashier cannot void a sale", r.status_code)
conn = raw()
chk(conn.execute("SELECT active FROM products WHERE id = ?", (pid,)).fetchone()[0] == 1,
    "the refused delete changed nothing")
conn.close()

# ------------------------------------------------ 5. manager PIN escalates the session
r = post(cash, f"/inventory/{pid}/delete", {"admin_pin": "pinpass"})
chk(r.status_code == 302, "manager PIN lets the cashier through once unlocked")
conn = raw()
chk(conn.execute("SELECT active FROM products WHERE id = ?", (pid,)).fetchone()[0] == 0,
    "the PIN-unlocked delete actually ran")
conn.close()
r = post(cash, f"/inventory/{pid}/adjust", {"direction": "out", "qty": "1", "reason": "shrinkage"})
conn = raw()
log = conn.execute("SELECT actor FROM inventory_logs WHERE reason = 'shrinkage'"
                   " ORDER BY id DESC LIMIT 1").fetchone()
conn.close()
chk(r.status_code == 302 and log and log["actor"] == "cash1+PIN",
    "PIN actions are attributed to the cashier, not blanked as admin", log and log["actor"])
chk(cash.get("/accounts").status_code == 200, "escalated session reaches Accounts")

# ----------------------------------------------------- 6. last active admin is safe
admin_uid = user_row("admin")["id"]
r = post(cash, f"/accounts/{admin_uid}/toggle")
chk(user_row("admin")["active"] == 1, "a cashier (even PIN-escalated) cannot disable the last admin")
r = post(cash, f"/accounts/{admin_uid}", {"role": "cashier"})
chk(user_row("admin")["role"] == "admin", "the last admin cannot be demoted")
r = post(admin, f"/accounts/{admin_uid}/toggle")
chk(user_row("admin")["active"] == 1, "even the admin cannot disable the last admin")

# -------------------------------------------------------------- 7. disable / enable
r = post(admin, "/accounts/%d/toggle" % user_row("cash1")["id"])
chk(user_row("cash1")["active"] == 0, "admin can disable an account")
_, r = login("cash1", "cashpass")
chk(r.status_code == 200, "a disabled account cannot log in")
post(admin, "/accounts/%d/toggle" % user_row("cash1")["id"])
chk(user_row("cash1")["active"] == 1, "admin can re-enable it")

# ------------------------------- 8. admin reset / delete, logs page, guards
r = post(admin, "/accounts/%d" % user_row("cash1")["id"], {"password": "brandnew"})
_, r2 = login("cash1", "brandnew")
chk(r2.status_code == 302, "admin can reset a password")
page = admin.get("/logs").get_data(as_text=True)
chk(admin.get("/logs").status_code == 200 and "cash1" in page, "admin sees activity logs with actors")
chk(cash.get("/logs").status_code == 401, "cashier cannot open Logs")
r = post(admin, "/accounts/%d/delete" % admin_uid)
chk(user_row("admin") is not None, "an admin cannot delete their own account")
post(admin, "/accounts/%d/delete" % user_row("cash1")["id"])
chk(user_row("cash1") is None, "admin can delete another account")

# ----------------------------------------------------------- 9. open redirect refused
r = A.app.test_client().get("/login", query_string={"nxt": "https://evil.example"})
html = r.get_data(as_text=True)
chk("https://evil.example" not in html, "nxt= outside the shop is refused")

print()
print("FAILED: " + ", ".join(fails) if fails else "all accounts checks pass")
sys.exit(1 if fails else 0)
