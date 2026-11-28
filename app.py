"""ERP with user accounts: POS main screen + Inventory with categories inside Inventory.

Two roles:
  admin   - everything, including deletes, edits, voids, sets and account management
  cashier - sell, restock (stock in), add fresh products, view inventory and sales
Run:  python3 app.py          -> http://127.0.0.1:5000
"""
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent


def load_dotenv():
    """Local-only .env loader; Vercel sets real environment variables instead."""
    path = BASE / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            # 'KEY=value   # note' -> 'value' (as .env.example writes them); quotes optional
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)


load_dotenv()
DB_PATH = Path(os.environ.get("ERP_DB") or (BASE / "erp.db"))
# Turso/libsql takes over as soon as TURSO_URL is set (alias: TURSO_DATABASE_URL).
TURSO_URL = os.environ.get("TURSO_URL") or os.environ.get("TURSO_DATABASE_URL") or ""
TURSO_TOKEN = os.environ.get("TURSO_TOKEN") or os.environ.get("TURSO_AUTH_TOKEN") or ""
CURRENCY = "₮"
VAT_PERCENT = 10.0


SHOP_TZ_NAME = os.environ.get("ERP_TZ") or "Asia/Ulaanbaatar"
try:
    from zoneinfo import ZoneInfo
    SHOP_TZ = ZoneInfo(SHOP_TZ_NAME)
except Exception:                     # no tz database at all - fall back to the server clock
    SHOP_TZ = None


def now_local():
    """Shop-local time, in the same text format SQLite's datetime() writes.

    SQLite's datetime('now','localtime') means the *server's* zone - UTC on Vercel and
    Turso - so every timestamp is written from here instead (ERP_TZ, default Ulaanbaatar)."""
    from datetime import datetime
    return datetime.now(SHOP_TZ).strftime("%Y-%m-%d %H:%M:%S")


def money(value):
    """1900000 -> '1,900,000₮' ; 1900000.5 -> '1,900,000.50₮'"""
    value = value or 0
    if abs(value - round(value)) < 1e-9:
        return f"{int(round(value)):,}{CURRENCY}"
    return f"{value:,.2f}{CURRENCY}"



PUBLIC = os.environ.get("ERP_PUBLIC") == "1"
# Off unless asked for: the Werkzeug debugger is a remote Python console for anyone who
# can reach the port (ERP_HOST=0.0.0.0 on a shop network, for one).
DEBUG_MODE = os.environ.get("ERP_DEBUG") == "1" and not PUBLIC
PASSWORD = os.environ.get("ERP_PASSWORD") or ""

app = Flask(__name__)
if PUBLIC and not os.environ.get("ERP_SECRET_KEY"):
    raise RuntimeError("ERP_PUBLIC=1 needs ERP_SECRET_KEY (stable sessions across restarts).")
app.secret_key = os.environ.get("ERP_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=PUBLIC)

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'self'; object-src 'none'")


@app.after_request
def security_headers(resp):
    """The templates use inline script and inline style, so 'unsafe-inline' stays -
    but nothing here may reach off-box, frame itself, or be sniffed as another type."""
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return resp


def wants_json():
    """True when the caller is fetch(), not a browser navigating."""
    return (request.headers.get("X-FX") == "1"
            or request.headers.get("X-Requested-With") == "xhr"
            or (request.headers.get("Accept") or "").startswith("application/json"))


# ------------------------------------------------------- login rate limiting
LOGIN_MAX_FAILS = int(os.environ.get("ERP_LOGIN_MAX_FAILS") or 5)
LOGIN_WINDOW = int(os.environ.get("ERP_LOGIN_WINDOW") or 300)
LOGIN_LOCK_BASE = int(os.environ.get("ERP_LOGIN_LOCK_SECONDS") or 30)
LOCK_CAP = 3600           # never lock anyone out for more than an hour at a time


def client_ip():
    """The caller's address for throttling.

    X-Forwarded-For is whatever the client typed, so it is never trusted by itself.
    On Vercel the edge overwrites X-Real-IP / X-Vercel-Forwarded-For with the real
    address; behind another proxy set ERP_TRUST_PROXY=1 to use the last hop it added."""
    if os.environ.get("VERCEL"):
        for header in ("X-Vercel-Forwarded-For", "X-Real-IP"):
            value = (request.headers.get(header) or "").split(",")[0].strip()
            if value:
                return value
    if os.environ.get("ERP_TRUST_PROXY") == "1":
        hops = [h.strip() for h in (request.headers.get("X-Forwarded-For") or "").split(",")]
        if hops and hops[-1]:
            return hops[-1]
    return request.remote_addr or "?"


def throttle_left(key):
    """Seconds left on a lockout, or None when the caller may try.

    Kept in the database, not in memory: on Vercel every cold start and every
    parallel instance would otherwise hand an attacker a fresh set of tries."""
    row = db().execute("SELECT locked FROM login_throttle WHERE key = ?", (key,)).fetchone()
    now = time.time()
    if row is not None and row["locked"] and now < row["locked"]:
        return int(row["locked"] - now) + 1
    return None


def throttle_fail(key):
    d = db()
    row = d.execute("SELECT fails, started FROM login_throttle WHERE key = ?", (key,)).fetchone()
    now = time.time()
    fails, started = (row["fails"], row["started"]) if row is not None else (0, now)
    if now - started > LOGIN_WINDOW:
        fails, started = 0, now
    fails += 1
    locked = 0.0
    if fails >= LOGIN_MAX_FAILS:
        locked = now + min(LOGIN_LOCK_BASE * 2 ** min(fails - LOGIN_MAX_FAILS, 12), LOCK_CAP)
    d.execute("INSERT INTO login_throttle (key, fails, started, locked) VALUES (?, ?, ?, ?)"
              " ON CONFLICT(key) DO UPDATE SET fails = excluded.fails,"
              " started = excluded.started, locked = excluded.locked",
              (key, fails, started, locked))
    # old rows would pile up forever otherwise
    d.execute("DELETE FROM login_throttle WHERE started < ? AND locked < ?",
              (now - 86400, now))
    d.commit()
    app.logger.warning("failed attempt for %s (%d in %ds window)", key, fails, LOGIN_WINDOW)
    return locked


def throttle_clear(key):
    db().execute("DELETE FROM login_throttle WHERE key = ?", (key,))
    db().commit()


# ------------------------------------------------------------------- accounts
ROLES = ("admin", "cashier")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,31}\Z")
MIN_PASSWORD_LEN = 6


def seed_users(conn):
    """First run: create one admin so the shop opens with a known login.
    Password order: ERP_ADMIN_PASSWORD, then the old ERP_PASSWORD, then generated."""
    if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return
    name = (os.environ.get("ERP_ADMIN_USER") or "admin").strip().lower()
    if not USERNAME_RE.match(name):
        name = "admin"
    password = os.environ.get("ERP_ADMIN_PASSWORD") or PASSWORD
    generated = not password
    if generated:
        password = secrets.token_urlsafe(9)
    conn.execute("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                 (name, generate_password_hash(password), now_local()))
    conn.commit()
    app.logger.info("seeded admin account '%s' from %s", name,
                    "ERP_ADMIN_PASSWORD" if os.environ.get("ERP_ADMIN_PASSWORD")
                    else "ERP_PASSWORD" if PASSWORD else "a generated password")
    if generated:
        app.logger.warning("created admin account '%s' with password '%s' - "
                           "log in and change it under Accounts.", name, password)


def current_user():
    """The logged-in user straight from the DB (cached per request), or None.
    Disabling an account locks its session out on the very next request."""
    if "user" in g:
        return g.user or None
    g.user = False
    if session.get("authed") and session.get("uid"):
        row = db().execute("SELECT id, username, role, active FROM users WHERE id = ?",
                           (session["uid"],)).fetchone()
        if row is not None and row["active"]:
            g.user = row
            session["uname"] = row["username"]
            session["role"] = row["role"]
    return g.user or None


def safe_next(nxt):
    """Only ever redirect to a path on this app - never to another host."""
    return nxt if nxt and nxt.startswith("/") and not nxt.startswith("//") else None


@app.before_request
def login_gate():
    """Every page needs a logged-in account; only login/logout/static are public."""
    if request.endpoint in ("login", "logout", "static"):
        return None
    if current_user():
        return None
    return redirect(url_for("login", nxt=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = safe_next(request.args.get("nxt")) or url_for("pos")
    if request.method == "POST":
        ip = "login:" + client_ip()
        left = throttle_left(ip)
        if left:
            app.logger.warning("login throttled for %s - %ds left", ip, left)
            flash(f"Too many wrong logins. Try again in {left}s.", "error")
            return render_template("login.html", nxt=nxt), 429
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        row = db().execute("SELECT id, username, role, pass_hash FROM users"
                           " WHERE username = ? AND active = 1", (username,)).fetchone()
        if row is not None and check_password_hash(row["pass_hash"], password):
            throttle_clear(ip)
            session.clear()
            session["authed"] = True
            session["uid"] = row["id"]
            session["uname"] = row["username"]
            session["role"] = row["role"]
            session["csrf"] = secrets.token_hex(16)   # fresh token per login
            session["cart"] = {}           # every cashier starts on a clean till
            session["sets"] = {}
            session["payments"] = []
            db().execute("UPDATE users SET last_login = ? WHERE id = ?",
                         (now_local(), row["id"]))
            db().commit()
            return redirect(safe_next(request.form.get("nxt")) or nxt)
        throttle_fail(ip)
        flash("Wrong username or password.", "error")
    return render_template("login.html", nxt=nxt)


@app.route("/logout")
def logout():
    for key in ("authed", "uid", "uname", "role", "admin_until",
                "cart", "sets", "payments", "customer"):
        session.pop(key, None)
    return redirect(url_for("login"))


# ------------------------------------------------- CSRF + admin PIN (tier 2)
# The manager PIN is its own secret. Older setups only had ERP_ADMIN_PASSWORD (which is
# also the seeded admin's login password); it still works as the PIN until a separate
# ERP_MANAGER_PIN is set, with a warning, so an existing shop keeps working.
ADMIN_PASSWORD = os.environ.get("ERP_MANAGER_PIN") or os.environ.get("ERP_ADMIN_PASSWORD") or ""
if ADMIN_PASSWORD and not os.environ.get("ERP_MANAGER_PIN"):
    app.logger.warning("manager PIN falls back to ERP_ADMIN_PASSWORD - set ERP_MANAGER_PIN "
                       "so the PIN is not also the admin account's password")
ADMIN_WINDOW = int(os.environ.get("ERP_ADMIN_WINDOW") or 900)
MAX_CART_LINES = int(os.environ.get("ERP_MAX_CART_LINES") or 60)
MAX_QTY_PER_LINE = int(os.environ.get("ERP_MAX_QTY_PER_LINE") or 999)
HELD_SCHEMA = 1        # bump when the held-cart blob layout changes; resume refuses mismatches


ADMIN_ONLY = {"product_edit", "product_delete", "product_purge", "product_restore",
              "category_edit", "category_delete", "set_new", "set_edit", "set_delete",
              "sale_void", "accounts", "account_new", "account_update", "account_toggle",
              "account_delete", "logs"}

@app.before_request
def csrf_gate():
    """Admin pages are gated on GET too (a cashier never sees the form), and the
    session token must come back on every mutating request (form field or header)."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    # The token check comes first and applies to admin routes too - an admin
    # session must never be able to delete or void on a forged request.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
        if not hmac.compare_digest(sent, session.get("csrf", "")):
            msg = "Session expired - reload the page and try again."
            if wants_json():
                return jsonify(ok=False, error=msg), 400
            return render_template("error.html", msg=msg), 400
    if request.endpoint in ADMIN_ONLY:
        return admin_gate()
    return None


def is_admin():
    """Admin by account role, or by manager-PIN escalation unlocked earlier (admin_gate)."""
    user = current_user()
    if user is not None and user["role"] == "admin":
        return True
    until = session.get("admin_until") or 0
    return time.time() < until


def admin_gate():
    """None when the caller may proceed, otherwise the PIN prompt to render."""
    if is_admin():
        return None
    # Body or header only - a PIN in the query string ends up in logs and history.
    sent = request.form.get("admin_pin") or request.headers.get("X-Admin-Pin") or ""
    msg = "Admin PIN required for this action."
    if sent and ADMIN_PASSWORD:
        user = current_user()
        key = f"pin:{user['id'] if user is not None else client_ip()}"
        left = throttle_left(key)
        if left:
            msg = f"Too many wrong PINs. Try again in {left}s."
        elif hmac.compare_digest(sent.encode(), ADMIN_PASSWORD.encode()):
            throttle_clear(key)
            session["admin_until"] = time.time() + ADMIN_WINDOW
            return None
        else:
            throttle_fail(key)
            msg = "Wrong PIN."
    if wants_json():
        # API / fetch callers must get JSON - a PIN form in an AJAX response is a parse error.
        return jsonify(ok=False, error=msg, code="ADMIN_REQUIRED"), 401
    return render_template("admin_pin.html", form=dict(request.form), pin_error=sent and msg,
                           back=request.path, admin_window=ADMIN_WINDOW), 401


def actor():
    """Who the audit trail blames - 'name+PIN' when a cashier used the manager PIN."""
    user = current_user()
    if user is None:
        return "anonymous"
    if user["role"] != "admin" and is_admin():
        return user["username"] + "+PIN"
    return user["username"]


# ------------------------------------------------------------ account management
def new_user_error(username, password, role):
    if not USERNAME_RE.match(username or ""):
        return ("Username must be 3-32 characters: lowercase letters, digits, "
                "dot, dash or underscore, starting with a letter or digit.")
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password needs at least {MIN_PASSWORD_LEN} characters."
    if role not in ROLES:
        return "Unknown role."
    return None


def is_last_active_admin(uid):
    row = db().execute("SELECT role, active FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None or row["role"] != "admin" or not row["active"]:
        return False
    others = db().execute("SELECT COUNT(*) AS n FROM users"
                          " WHERE role = 'admin' AND active = 1 AND id <> ?", (uid,)).fetchone()
    return others["n"] == 0


@app.route("/accounts")
def accounts():
    rows = db().execute("SELECT id, username, role, active, created_at, last_login"
                        " FROM users ORDER BY role DESC, username").fetchall()
    return render_template("accounts.html", users=rows, roles=ROLES,
                           min_len=MIN_PASSWORD_LEN)


@app.route("/accounts/new", methods=["POST"])
def account_new():
    username = (request.form.get("username") or "").strip().lower()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "cashier").strip()
    err = new_user_error(username, password, role)
    if err:
        flash(err, "error")
        return redirect(url_for("accounts"))
    try:
        db().execute("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)",
                     (username, generate_password_hash(password), role, now_local()))
        db().commit()
        flash(f"Account {username} created as {role}.", "ok")
    except sqlite3.IntegrityError:
        db().rollback()
        flash("That username already exists.", "error")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:uid>", methods=["POST"])
def account_update(uid):
    user = db().execute("SELECT id, username, role, active FROM users WHERE id = ?",
                        (uid,)).fetchone()
    if user is None:
        flash("Account not found.", "error")
        return redirect(url_for("accounts"))
    role = (request.form.get("role") or user["role"]).strip()
    password = request.form.get("password") or ""
    if role not in ROLES:
        flash("Unknown role.", "error")
        return redirect(url_for("accounts"))
    demoting = user["role"] == "admin" and (role != "admin" or not user["active"])
    if demoting and is_last_active_admin(uid):
        flash("Cannot demote the last active admin.", "error")
        return redirect(url_for("accounts"))
    if role != user["role"]:
        db().execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
        session.pop("admin_until", None)     # a role change re-decides the current session
    if password:
        if len(password) < MIN_PASSWORD_LEN:
            db().rollback()
            flash(f"Password needs at least {MIN_PASSWORD_LEN} characters.", "error")
            return redirect(url_for("accounts"))
        db().execute("UPDATE users SET pass_hash = ? WHERE id = ?",
                     (generate_password_hash(password), uid))
        if uid == session.get("uid"):
            flash("Your password was changed.", "ok")
    db().commit()
    flash(f"Account {user['username']} updated.", "ok")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:uid>/toggle", methods=["POST"])
def account_toggle(uid):
    user = db().execute("SELECT id, username, role, active FROM users WHERE id = ?",
                        (uid,)).fetchone()
    if user is None:
        flash("Account not found.", "error")
        return redirect(url_for("accounts"))
    if user["active"] and is_last_active_admin(uid):
        flash("Cannot disable the last active admin.", "error")
        return redirect(url_for("accounts"))
    db().execute("UPDATE users SET active = ? WHERE id = ?", (0 if user["active"] else 1, uid))
    db().commit()
    if uid == session.get("uid") and user["active"]:
        return redirect(url_for("logout"))   # switched myself off
    flash(f"Account {user['username']} " + ("disabled." if user["active"] else "enabled."), "ok")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:uid>/delete", methods=["POST"])
def account_delete(uid):
    user = db().execute("SELECT id, username, role, active FROM users WHERE id = ?",
                        (uid,)).fetchone()
    if user is None:
        flash("Account not found.", "error")
        return redirect(url_for("accounts"))
    if uid == session.get("uid"):
        flash("You cannot delete your own account - disable it instead.", "error")
        return redirect(url_for("accounts"))
    if user["role"] == "admin" and user["active"] and is_last_active_admin(uid):
        flash("Cannot delete the last active admin.", "error")
        return redirect(url_for("accounts"))
    db().execute("DELETE FROM users WHERE id = ?", (uid,))
    db().commit()
    flash(f"Account {user['username']} deleted.", "ok")
    return redirect(url_for("accounts"))


@app.route("/logs")
def logs():
    """Admin-only audit trail: every stock move - who did it, what changed, why."""
    q = (request.args.get("q") or "").strip()
    sql = ("SELECT l.id, l.created_at, l.actor, l.reason, l.old_qty, l.new_qty, l.delta,"
           " COALESCE(p.name, '(deleted product)') AS name, l.sale_id"
           " FROM inventory_logs l LEFT JOIN products p ON p.id = l.product_id")
    args: list = []
    if q:
        sql += " WHERE p.name LIKE ? OR l.actor LIKE ? OR l.reason LIKE ?"
        like = f"%{q}%"
        args = [like, like, like]
    sql += " ORDER BY l.id DESC LIMIT 300"
    rows = db().execute(sql, args).fetchall()
    return render_template("logs.html", rows=rows, q=q)


@app.context_processor
def security_globals():
    from markupsafe import Markup
    return {"csrf_token": session.get("csrf", ""),
            "csrf_field": Markup('<input type="hidden" name="csrf" value="'
                                   + session.get("csrf", "") + '">'),
            "is_admin": is_admin(),
            "me": current_user(),
            "ADMIN_ON": bool(ADMIN_PASSWORD)}

app.jinja_env.globals["CURRENCY"] = CURRENCY
app.jinja_env.globals["VAT_PERCENT"] = VAT_PERCENT
app.jinja_env.filters["money"] = money


def asset_v(filename):
    """Cache-buster so CSS changes show up on a plain reload."""
    try:
        return int((BASE / "static" / filename).stat().st_mtime)
    except OSError:
        return 0


app.jinja_env.globals["asset_v"] = asset_v

# Bump this whenever SCHEMA/migrations below change - it is what lets a hosted
# database skip the whole migration crawl on boot (6.7s of round trips -> 2).
SCHEMA_VERSION = "8"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sku TEXT UNIQUE,
    name TEXT NOT NULL,
    cost REAL NOT NULL DEFAULT 0,
    price REAL NOT NULL DEFAULT 0,
    qty INTEGER NOT NULL DEFAULT 0,
    low_stock_at INTEGER NOT NULL DEFAULT 5,
    n_search TEXT NOT NULL DEFAULT '',
    n_sku TEXT NOT NULL DEFAULT '',
    n_barcode TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ref TEXT NOT NULL UNIQUE,
    total REAL NOT NULL,
    paid REAL NOT NULL DEFAULT 0,
    change REAL NOT NULL DEFAULT 0,
    item_count INTEGER NOT NULL,
    customer_phone TEXT,
    customer_note TEXT,
    n_search TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    amount REAL NOT NULL,
    note TEXT,
    n_note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    qty INTEGER NOT NULL,
    line_total REAL NOT NULL,
    n_name TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS payment_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    commission_percent REAL NOT NULL DEFAULT 0,
    commission_mode TEXT NOT NULL DEFAULT 'ABSORBED'
        CHECK (commission_mode IN ('ABSORBED','SURCHARGE')),
    active INTEGER NOT NULL DEFAULT 1,
    sort INTEGER NOT NULL DEFAULT 0,
    requires_note INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS held_carts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    label TEXT,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    price REAL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS set_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id INTEGER NOT NULL REFERENCES sets(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    qty INTEGER NOT NULL DEFAULT 1,
    UNIQUE (set_id, product_id)
);
/* FK columns - every one of these is a separate Turso round trip per sale page,
   receipt and set breakdown, so they must not be full scans. */
CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);
CREATE INDEX IF NOT EXISTS idx_sale_items_product ON sale_items(product_id);
CREATE INDEX IF NOT EXISTS idx_payments_sale ON payments(sale_id);
CREATE INDEX IF NOT EXISTS idx_set_products_set ON set_products(set_id);
CREATE TABLE IF NOT EXISTS inventory_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    old_qty INTEGER,
    new_qty INTEGER,
    delta INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    actor TEXT,
    sale_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS login_throttle (
    key TEXT PRIMARY KEY,
    fails INTEGER NOT NULL DEFAULT 0,
    started REAL NOT NULL DEFAULT 0,
    locked REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    closed_at TEXT,
    opening_float REAL NOT NULL DEFAULT 0,
    counted_cash REAL,
    drops REAL NOT NULL DEFAULT 0,
    note TEXT
);
/* One permanent row: a stock guard that fails inserts id 1 a second time and
   aborts the whole checkout transaction instead of going negative. */
CREATE TABLE IF NOT EXISTS stock_guards (id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','cashier')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    last_login TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_inv_logs_product ON inventory_logs(product_id);
CREATE INDEX IF NOT EXISTS idx_inv_logs_created ON inventory_logs(created_at);
"""

PRODUCT_COLUMNS = [
    ("barcode", "TEXT"),
    ("brand", "TEXT"),
    ("model", "TEXT"),
    ("specifications", "TEXT"),
    ("category_id", "INTEGER REFERENCES categories(id) ON DELETE SET NULL"),
    ("supplier_id", "INTEGER REFERENCES suppliers(id) ON DELETE SET NULL"),
    ("active", "INTEGER NOT NULL DEFAULT 1"),
    ("n_search", "TEXT NOT NULL DEFAULT ''"),
    ("n_sku", "TEXT NOT NULL DEFAULT ''"),
    ("n_barcode", "TEXT NOT NULL DEFAULT ''"),
]
PAYMENT_COLUMNS = [
    ("commission_percent", "REAL NOT NULL DEFAULT 0"),
    ("commission_mode", "TEXT"),
    ("commission_amount", "REAL NOT NULL DEFAULT 0"),
    ("note", "TEXT"),
    ("n_note", "TEXT NOT NULL DEFAULT ''"),
]
SALE_COLUMNS = [
    ("vat_amount", "REAL NOT NULL DEFAULT 0"),
    ("customer_phone", "TEXT"),
    ("customer_note", "TEXT"),
    ("paid", "REAL NOT NULL DEFAULT 0"),
    ("change", "REAL NOT NULL DEFAULT 0"),
    ("n_search", "TEXT NOT NULL DEFAULT ''"),
    ("voided_at", "TEXT"),
    ("voided_by", "TEXT"),
]
SALE_ITEM_COLUMNS = [
    ("set_id", "INTEGER REFERENCES sets(id) ON DELETE SET NULL"),
    ("n_name", "TEXT NOT NULL DEFAULT ''"),
]
PAYMENT_SEED = [
    ("cash", "Cash", 0, "ABSORBED", 1, 10, 0),
    ("card", "Credit card", 0, "ABSORBED", 1, 20, 0),
    ("bank", "Bank transfer", 0, "ABSORBED", 1, 30, 0),
    ("mobile", "Mobile wallet", 0, "ABSORBED", 1, 40, 0),
    ("leasing", "Leasing", 0, "ABSORBED", 1, 50, 1),
]
# methods that need a note typed in (which leasing app / provider the client used)
NOTE_REQUIRED_KEYS = {"leasing"}


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


class Row:
    """sqlite3.Row lookalike - dict-style rows from local SQLite and Turso alike."""
    __slots__ = ("_names", "_vals")

    def __init__(self, names, vals):
        self._names = names
        self._vals = tuple(vals)

    def keys(self):
        return list(self._names)

    def items(self):
        return list(zip(self._names, self._vals))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key]
        return self._vals[self._names.index(key)]

    def __contains__(self, key):
        return key in self._names if isinstance(key, str) else key in self._vals

    def __iter__(self):
        return iter(self._vals)

    def __len__(self):
        return len(self._vals)

    def __repr__(self):
        return repr(self._vals)


class Result:
    """One cursor face for both sqlite3 and libsql."""

    def __init__(self, cur):
        self.lastrowid = cur.lastrowid
        self.rowcount = cur.rowcount
        # libsql reports some column names uppercased (key -> KEY); the app speaks lowercase.
        self._names = [str(d[0] or "").lower() for d in cur.description] if cur.description else []
        self._rows = cur.fetchall() if cur.description else []

    def fetchall(self):
        return [Row(self._names, r) for r in self._rows]

    def fetchone(self):
        return Row(self._names, self._rows[0]) if self._rows else None

    def fetchmany(self, size=None):
        take = len(self._rows) if size is None else size
        out = [Row(self._names, r) for r in self._rows[:take]]
        self._rows = self._rows[take:]
        return out

    def __iter__(self):
        return iter(self.fetchall())


def as_sqlite_error(exc):
    """libsql reports constraint clashes as plain ValueError; keep one exception face."""
    msg = str(exc)
    if "SQLITE_CONSTRAINT" in msg or "UNIQUE constraint" in msg or "FOREIGN KEY" in msg:
        return sqlite3.IntegrityError(msg)
    return exc


SAFE_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def ident(name):
    """Table / column name veto - identifiers can't be bound as parameters, so any
    SQL built from a dynamic name has to pass here first."""
    name = str(name)
    if not SAFE_IDENT.match(name):
        raise ValueError(f"refusing unsafe SQL identifier: {name!r}")
    return name


LOG_SQL = """INSERT INTO inventory_logs (product_id, old_qty, new_qty, delta, reason, actor, sale_id,
                                        created_at)
             SELECT id, qty, qty + ?, ?, ?, ?, ?, ? FROM products WHERE id = ?"""


def log_params(pid, delta, reason, sale_id=None, who=None):
    return (delta, delta, reason, who or actor(), sale_id, now_local(), pid)


def log_stock(conn, pid, delta, reason, sale_id=None):
    """One row per stock change: who, how much, why, when."""
    conn.execute(LOG_SQL, log_params(pid, delta, reason, sale_id))


class DB:
    """Thin adapter so a single code path serves local SQLite and hosted Turso."""

    def __init__(self, conn):
        self._c = conn

    def _guard(self, fn, *args):
        try:
            return fn(*args)
        except sqlite3.Error:
            raise
        except Exception as exc:
            raise as_sqlite_error(exc) from exc

    def execute(self, sql, args=()):
        return Result(self._guard(self._c.execute, sql, tuple(args)))

    def executemany(self, sql, seq):
        return Result(self._guard(self._c.executemany, sql, [tuple(x) for x in seq]))

    def executescript(self, sql):
        self._guard(self._c.executescript, sql)

    def script(self, statements):
        """One transaction: the whole checkout travels together.

        A statement is plain SQL or a (sql, params) pair - and when params is a list
        of pairs it becomes one executemany, so a 12-line cart is a handful of round
        trips instead of a hundred. Values are bound, never formatted into SQL.

        A failing statement (a stock guard, a unique clash) aborts every statement
        in the script, so no half-written sale can survive.
        """
        nested = bool(getattr(self._c, "in_transaction", False))
        if not nested:
            self.execute("BEGIN IMMEDIATE")
        try:
            for st in statements:
                if isinstance(st, tuple):
                    sql, params = st
                    batch = isinstance(params, list) and all(isinstance(p, tuple) for p in params)
                    self.executemany(sql, params) if batch else self.execute(sql, tuple(params))
                else:
                    self.execute(st)
        except Exception:
            if not nested:
                self.rollback()
            raise
        if not nested:
            self.commit()

    def commit(self):
        self._guard(self._c.commit)

    def rollback(self):
        self._guard(self._c.rollback)

    def close(self):
        try:
            self._c.close()
        except Exception:
            pass


def connect():
    if TURSO_URL:
        import libsql
        conn = DB(libsql.connect(TURSO_URL, auth_token=TURSO_TOKEN))
    else:
        raw = sqlite3.connect(DB_PATH)
        raw.row_factory = sqlite3.Row
        conn = DB(raw)
    # SQLite ignores REFERENCES ... ON DELETE unless this is switched on, per connection.
    try:
        conn.execute("PRAGMA foreign_keys = ON")
    except Exception as exc:                          # a backend without the pragma
        app.logger.warning("could not enable foreign keys: %s", exc)
    return conn


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


# ---------------------------------------------- search plumbing
def norm(value):
    return str(value if value is not None else "").casefold()


def query_words(raw):
    """'rtx 5060' -> ['rtx', '5060'] - each word must match somewhere."""
    return [w for w in re.split(r"\s+", (raw or "").strip()) if w]


def like_terms(text):
    """%word% with the user's own % and _ escaped so they stay literal."""
    escaped = norm(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def match_any(columns, value):
    """(col LIKE ? OR ...) for one word across already casefolded search columns.

    The folds live in the rows (n_search / n_note / n_name) rather than in a
    SQLite UDF, because Turso/libsql cannot register Python functions and its
    own lower() leaves Cyrillic untouched.
    """
    clause = " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in columns)
    like = like_terms(value)
    return f"({clause})", [like] * len(columns)


def all_words(columns, raw):
    """Every typed word must match at least one column. Returns (clause, args)."""
    clauses, args = [], []
    for word in query_words(raw):
        clause, extra = match_any(columns, word)
        clauses.append(clause)
        args += extra
    return (" AND ".join(clauses), args)


def product_columns():
    return ["p.n_search"]


def blob_of(*parts):
    """Casefolded haystack built from the searchable text of one row."""
    return norm(" ".join(str(p if p is not None else "") for p in parts))


def product_stamp(sku, name, barcode, brand):
    return (blob_of(name, sku, barcode, brand), norm(sku), norm(barcode))


def add_columns(conn, table, columns):
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({ident(table)})")}
    for name, decl in columns:
        if name not in have:
            conn.execute(f"ALTER TABLE {ident(table)} ADD COLUMN {ident(name)} {decl}")


def backfill_search(conn):
    """Fill the casefolded search columns for rows written before they existed.

    Python casefolds Cyrillic correctly; SQLite lower() (and libsql's) does not,
    which is why the fold has to happen here in Python and not in SQL.
    """
    for r in conn.execute("SELECT id, sku, name, barcode, brand FROM products"
                          " WHERE n_search IS NULL OR n_search = ''").fetchall():
        blob, n_sku, n_barcode = product_stamp(r["sku"], r["name"], r["barcode"], r["brand"])
        conn.execute("UPDATE products SET n_search=?, n_sku=?, n_barcode=? WHERE id=?",
                     (blob, n_sku, n_barcode, r["id"]))
    for r in conn.execute("SELECT id, ref, customer_phone, customer_note FROM sales"
                          " WHERE n_search IS NULL OR n_search = ''").fetchall():
        conn.execute("UPDATE sales SET n_search=? WHERE id=?",
                     (blob_of(r["ref"], r["customer_phone"], r["customer_note"]), r["id"]))
    for r in conn.execute("SELECT id, name FROM sale_items"
                          " WHERE n_name IS NULL OR n_name = ''").fetchall():
        conn.execute("UPDATE sale_items SET n_name=? WHERE id=?", (norm(r["name"]), r["id"]))
    for r in conn.execute("SELECT id, note FROM payments"
                          " WHERE n_note IS NULL OR n_note = ''").fetchall():
        conn.execute("UPDATE payments SET n_note=? WHERE id=?", (norm(r["note"]), r["id"]))


def init_db(conn=None):
    """Create/upgrade the schema on Turso (or on any connection you hand it)."""
    own = conn is None
    conn = conn or connect()
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    marker = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if marker is not None and marker["value"] == SCHEMA_VERSION:
        seed_users(conn)             # cheap SELECT; re-seeds if the table is somehow empty
        conn.commit()
        if own:
            conn.close()
        return                       # already built: 4 round trips instead of ~30
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO stock_guards (id) VALUES (1)")
    add_columns(conn, "products", PRODUCT_COLUMNS)
    add_columns(conn, "payments", PAYMENT_COLUMNS)
    add_columns(conn, "sale_items", SALE_ITEM_COLUMNS)

    # These need columns that ALTER TABLE added, so they come after add_columns.
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_products_active_name ON products(active, name);
        CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
        CREATE INDEX IF NOT EXISTS idx_sets_active ON sets(active, name);
    """)

    cols = {r[1] for r in conn.execute("PRAGMA table_info(sales)").fetchall()}
    add_columns(conn, "sales", SALE_COLUMNS)
    if "paid" not in cols or "change" not in cols:
        conn.execute("UPDATE sales SET paid = total WHERE paid = 0")

    add_columns(conn, "payment_methods",
                [("requires_note", "INTEGER NOT NULL DEFAULT 0")])
    conn.executemany(
        "INSERT OR IGNORE INTO payment_methods"
        " (key, label, commission_percent, commission_mode, active, sort, requires_note)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)", PAYMENT_SEED)
    keys = ",".join(f"'{k}'" for k in sorted(NOTE_REQUIRED_KEYS))
    conn.execute(f"UPDATE payment_methods SET requires_note = 1"
                 f" WHERE key IN ({keys}) AND requires_note <> 1")
    conn.execute(f"UPDATE payment_methods SET requires_note = 0"
                 f" WHERE key NOT IN ({keys}) AND requires_note <> 0")
    seed_users(conn)
    backfill_search(conn)
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (SCHEMA_VERSION,))
    conn.commit()
    if own:
        conn.close()


def payment_rows(active_only=False):
    cache = g.setdefault("payment_rows", {})      # one round trip per request, not five
    if active_only in cache:
        return cache[active_only]
    sql = "SELECT * FROM payment_methods"
    if active_only:
        sql += " WHERE active = 1"
    cache[active_only] = db().execute(sql + " ORDER BY sort, id").fetchall()
    return cache[active_only]


def payment_map():
    return {r["key"]: dict(r) for r in payment_rows()}


def surcharge_of(pm, amount):
    if pm is None or not pm.get("commission_percent"):
        return 0.0
    if pm.get("commission_mode") != "SURCHARGE":
        return 0.0
    return round(amount * pm["commission_percent"] / 100.0, 2)


def absorbed_of(pm, amount):
    if pm is None or not pm.get("commission_percent"):
        return 0.0
    if pm.get("commission_mode") != "ABSORBED":
        return 0.0
    return round(amount * pm["commission_percent"] / 100.0, 2)


def vat_of(goods_total):
    if not session.get("vat"):
        return 0.0
    return round(goods_total * VAT_PERCENT / 100.0, 2)


def surcharge_total(pays):
    """Fees the customer pays on top for SURCHARGE methods (e.g. card +2%)."""
    pm = payment_map()
    return round(sum(surcharge_of(pm.get(p["method"]), p["amount"]) for p in pays), 2)


def pay_totals(conn, pays, goods_total):
    """A surcharge rides on its payment line: the line's amount covers goods + VAT,
    the fee is charged on top. So it is added to both the total and what was paid,
    and the balance (what is still owed for the goods) does not move."""
    vat = vat_of(goods_total)
    fee = surcharge_total(pays)
    total = round(goods_total + vat + fee, 2)
    paid = round(sum(p["amount"] for p in pays) + fee, 2)
    return total, paid, vat


def category_rows():
    """Once per request - several views in the same request want the same chips."""
    cached = getattr(g, "_category_rows", None)
    if cached is None:
        cached = db().execute("""SELECT c.*, COUNT(p.id) AS product_count FROM categories c
                                LEFT JOIN products p ON p.category_id = c.id AND p.active = 1
                                GROUP BY c.id ORDER BY c.name""").fetchall()
        g._category_rows = cached
    return cached


def supplier_rows():
    cached = getattr(g, "_supplier_rows", None)
    if cached is None:
        cached = db().execute("""SELECT s.*, COUNT(p.id) AS product_count FROM suppliers s
                                LEFT JOIN products p ON p.supplier_id = s.id AND p.active = 1
                                GROUP BY s.id ORDER BY s.name""").fetchall()
        g._supplier_rows = cached
    return cached


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- inventory
SORT_COLUMNS = {
    "name": ("p.name", True),
    "category": ("c.name", True),
    "brand": ("p.brand", True),
    "cost": ("p.cost", False),
    "retail": ("p.price", False),
    "stock": ("p.qty", False),
    "supplier": ("s.name", True),
}


def sort_args():
    sort = (request.args.get("sort") or "name").strip().lower()
    if sort not in SORT_COLUMNS:
        sort = "name"
    sdir = "desc" if (request.args.get("sdir") or "asc").strip().lower() == "desc" else "asc"
    return sort, sdir


def order_by(sort, sdir):
    col, is_text = SORT_COLUMNS[sort]
    if is_text:
        expr = f"IFNULL({col}, '') COLLATE NOCASE"
    else:
        expr = f"IFNULL({col}, 0)"
    return f"ORDER BY {expr} {sdir.upper()}, p.id"


def product_rows(q, cat_id, low, sort, sdir):
    """Active products matching the inventory filter bar, in the requested order."""
    d = db()
    where = "p.active = 1"
    args = []
    if q:
        clause, extra = all_words(product_columns(), q)
        if clause:
            where += f" AND {clause}"
            args += extra
    if cat_id is not None:
        where += " AND p.category_id = ?"
        args.append(cat_id)

    sql = """SELECT p.*, c.name AS category, s.name AS supplier
             FROM products p
             LEFT JOIN categories c ON c.id = p.category_id
             LEFT JOIN suppliers s ON s.id = p.supplier_id
             WHERE """ + where + " " + order_by(sort, sdir)
    rows = [dict(r) for r in d.execute(sql, args).fetchall()]
    if low in ("1", "on", "yes"):
        rows = [r for r in rows if r["qty"] <= r["low_stock_at"]]
    return rows, sum(1 for r in rows if r["qty"] <= r["low_stock_at"])


@app.route("/inventory")
def inventory():
    d = db()
    tab = (request.args.get("tab") or "products").lower()
    sort, sdir = sort_args()
    categories = category_rows()

    if tab == "sets":
        rows = []
        for s in d.execute("""SELECT s.*, COUNT(sp.id) AS component_count
                             FROM sets s
                             LEFT JOIN set_products sp ON sp.set_id = s.id
                             WHERE s.active = 1 GROUP BY s.id ORDER BY s.name""").fetchall():
            s = dict(s)
            comps = set_components(d, s["id"])
            s["components"] = comps
            s["unit_price"], s["base_price"] = set_price_of(s, comps)
            max_sets = 9999
            for c in comps:
                max_sets = min(max_sets, c["stock"] // max(c["per_set"], 1))
            s["missing"] = missing_set_components(d, s["id"])
            s["can_sell"] = 0 if s["missing"] or not comps else max(0, max_sets)
            rows.append(s)
        return render_template("inventory.html", tab="sets", sets=rows, sort=sort, sdir=sdir)

    if tab == "categories":
        return render_template("inventory.html", tab=tab, categories=categories, sort=sort, sdir=sdir)

    if tab == "deleted":
        rows = [dict(r) for r in d.execute("""SELECT p.*, c.name AS category, s.name AS supplier
                                             FROM products p
                                             LEFT JOIN categories c ON c.id = p.category_id
                                             LEFT JOIN suppliers s ON s.id = p.supplier_id
                                             WHERE p.active = 0 """ + order_by(sort, sdir)).fetchall()]
        return render_template("inventory.html", tab=tab, products=rows, categories=categories,
                               sort=sort, sdir=sdir)

    q = request.args.get("q", "").strip()
    cat_id = to_int(request.args.get("cat"))
    low = request.args.get("low", "")
    rows, low_count = product_rows(q, cat_id, low, sort, sdir)

    return render_template("inventory.html", tab="products", products=rows, q=q,
                           cat_id=cat_id, low=low, low_count=low_count,
                           categories=categories, sort=sort, sdir=sdir)


@app.route("/inventory/search")
def inventory_search():
    """Live filter for the inventory bar: same rows as /inventory, but only the
    table body, so typing never reloads the page or rewrites the URL."""
    sort, sdir = sort_args()
    q = request.args.get("q", "").strip()
    cat_id = to_int(request.args.get("cat"))
    low = request.args.get("low", "")
    filtered = bool(q) or cat_id is not None or low in ("1", "on", "yes")
    rows, low_count = product_rows(q, cat_id, low, sort, sdir)
    return jsonify(
        rows=render_template("_inv_rows.html", products=rows),
        count=len(rows),
        note=f"{len(rows)} product(s)"
             + (f" - {low_count} at or under reorder level" if low_count else ""),
        empty=("No products match these filters." if filtered
               else "No products yet - add your first one."),
    )


@app.route("/inventory/deleted")
def inventory_deleted():
    return redirect(url_for("inventory", tab="deleted"))


def product_form_errors(form):
    name = (form.get("name") or "").strip()
    if not name:
        return "Name is required."
    # parse_amount, not float(): float() takes 'nan', 'inf' and '1e9', and a NaN price
    # would poison every total it touches.
    cost = parse_amount(form.get("cost") or "0")
    price = parse_amount(form.get("price") or "0")
    try:
        qty = int(form.get("qty") or 0)
        low = int(form.get("low_stock_at") or 5)
    except ValueError:
        qty = low = None
    if cost is None or price is None or qty is None or low is None:
        return "Cost and price must be amounts (up to 2 decimals), quantities whole numbers."
    if qty < 0 or low < 0:
        return "Values cannot be negative."
    return None


def form_values(form):
    return ((form.get("sku") or "").strip() or None,
            (form.get("name") or "").strip(),
            parse_amount(form.get("cost") or "0"),
            parse_amount(form.get("price") or "0"),
            int(form.get("qty") or 0),
            int(form.get("low_stock_at") or 5),
            (form.get("barcode") or "").strip() or None,
            (form.get("brand") or "").strip() or None,
            (form.get("model") or "").strip() or None,
            (form.get("specifications") or "").strip() or None,
            to_int(form.get("category_id")),
            to_int(form.get("supplier_id")))


def render_product_form(p, action):
    return render_template("product_form.html", p=p, action=action,
                           categories=category_rows(), suppliers=supplier_rows())


@app.route("/inventory/new", methods=["GET", "POST"])
def product_new():
    if request.method == "POST":
        err = product_form_errors(request.form)
        if err:
            flash(err, "error")
            return render_product_form(request.form, "Create")
        values = form_values(request.form)
        try:
            cur = db().execute(
                """INSERT INTO products (sku, name, cost, price, qty, low_stock_at, barcode,
                                         brand, model, specifications, category_id, supplier_id,
                                         active, n_search, n_sku, n_barcode, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                (*values, *product_stamp(values[0], values[1], values[6], values[7]), now_local()))
            new_id = cur.lastrowid
            if values[4]:
                # the opening stock is a stock move like any other
                db().execute("""INSERT INTO inventory_logs
                                (product_id, old_qty, new_qty, delta, reason, actor, created_at)
                                VALUES (?, 0, ?, ?, 'new product', ?, ?)""",
                             (new_id, values[4], values[4], actor(), now_local()))
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            flash("That SKU already exists.", "error")
            return render_product_form(request.form, "Create")
        flash("Product added.", "ok")
        return redirect(url_for("inventory"))
    return render_product_form(None, "Create")


@app.route("/inventory/<int:pid>/edit", methods=["GET", "POST"])
def product_edit(pid):
    p = db().execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        flash("Product not found.", "error")
        return redirect(url_for("inventory"))
    if request.method == "POST":
        err = product_form_errors(request.form)
        if err:
            flash(err, "error")
            return render_product_form(request.form, "Save")
        values = form_values(request.form)
        try:
            # Typing a new number on the form is still a stock move - log it against the
            # stock as it is right now (a sale may have landed since the form opened).
            db().execute("""INSERT INTO inventory_logs
                            (product_id, old_qty, new_qty, delta, reason, actor, created_at)
                            SELECT id, qty, ?, ? - qty, 'edited on product form', ?, ?
                            FROM products WHERE id = ? AND qty <> ?""",
                         (values[4], values[4], actor(), now_local(), pid, values[4]))
            db().execute(
                """UPDATE products SET sku=?, name=?, cost=?, price=?, qty=?, low_stock_at=?,
                       barcode=?, brand=?, model=?, specifications=?, category_id=?, supplier_id=?,
                       n_search=?, n_sku=?, n_barcode=?
                   WHERE id=?""",
                (*values, *product_stamp(values[0], values[1], values[6], values[7]), pid))
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            flash("That SKU already exists.", "error")
            return render_product_form(request.form, "Save")
        flash("Product updated.", "ok")
        return redirect(url_for("inventory"))
    return render_product_form(p, "Save")


@app.route("/inventory/<int:pid>/adjust", methods=["GET", "POST"])
def product_adjust(pid):
    d = db()
    p = d.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        flash("Product not found.", "error")
        return redirect(url_for("inventory"))
    if request.method == "POST":
        try:
            qty = int(request.form.get("qty") or 0)
        except ValueError:
            qty = -1
        direction = request.form.get("direction")
        if direction not in ("in", "out"):
            flash("Pick stock in or stock out.", "error")
        elif qty <= 0:
            flash("Quantity must be a positive whole number.", "error")
        else:
            if direction == "out" and not is_admin():
                # cashiers restock; taking stock out (damage, loss, shrinkage) needs the admin tier
                gate = admin_gate()
                if gate:
                    return gate          # PIN accepted -> falls through and applies at once
            delta = qty if direction == "in" else -qty
            reason = (request.form.get("reason") or "manual adjustment").strip()[:200]
            try:
                # Relative update in one transaction: a sale landing between the page
                # load and this POST is never overwritten, and stock can't go negative.
                d.script([
                    ("INSERT INTO stock_guards (id) SELECT 1 FROM products"
                     " WHERE id = ? AND qty + ? < 0", (pid, delta)),
                    (LOG_SQL, log_params(pid, delta, reason)),
                    ("UPDATE products SET qty = qty + ? WHERE id = ?", (delta, pid)),
                ])
            except sqlite3.IntegrityError:
                now = d.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()
                flash(f"Cannot remove {qty} - only {now['qty'] if now else 0} in stock.", "error")
            else:
                now = d.execute("SELECT qty FROM products WHERE id = ?", (pid,)).fetchone()
                flash(f"Stock updated: {p['name']} now {now['qty']}.", "ok")
                return redirect(url_for("inventory"))
            p = d.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    return render_template("adjust.html", p=p)


@app.route("/inventory/<int:pid>/delete", methods=["POST"])
def product_delete(pid):
    db().execute("UPDATE products SET active = 0 WHERE id = ?", (pid,))
    db().commit()
    flash("Product deleted. Restore it from Inventory > Deleted.", "ok")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:pid>/restore", methods=["POST"])
def product_restore(pid):
    db().execute("UPDATE products SET active = 1 WHERE id = ?", (pid,))
    db().commit()
    flash("Product restored.", "ok")
    return redirect(url_for("inventory", tab="deleted"))


@app.route("/inventory/<int:pid>/purge", methods=["POST"])
def product_purge(pid):
    in_sets = db().execute("""SELECT s.name FROM set_products sp JOIN sets s ON s.id = sp.set_id
                              WHERE sp.product_id = ? ORDER BY s.name""", (pid,)).fetchall()
    if in_sets:
        # Purging would silently drop it from these sets and change what they sell.
        flash("Cannot delete permanently - it is a component of: "
              + ", ".join(r["name"] for r in in_sets) + ". Edit those sets first.", "error")
        return redirect(url_for("inventory", tab="deleted"))
    db().execute("DELETE FROM products WHERE id = ?", (pid,))
    db().commit()
    flash("Product deleted permanently. Past sales are kept.", "ok")
    return redirect(url_for("inventory", tab="deleted"))


# --------------------------------------------------- categories inside inventory
@app.route("/inventory/categories/add", methods=["POST"])
def category_add():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Category name is required.", "error")
    else:
        try:
            db().execute("INSERT INTO categories (name, created_at) VALUES (?, ?)",
                         (name, now_local()))
            db().commit()
            flash("Category added.", "ok")
        except sqlite3.IntegrityError:
            db().rollback()
            flash("That category already exists.", "error")
    return redirect(url_for("inventory", tab="categories"))


@app.route("/inventory/categories/<int:cid>/edit", methods=["POST"])
def category_edit(cid):
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Category name is required.", "error")
    else:
        try:
            db().execute("UPDATE categories SET name = ? WHERE id = ?", (name, cid))
            db().commit()
            flash("Category renamed.", "ok")
        except sqlite3.IntegrityError:
            db().rollback()
            flash("That category already exists.", "error")
    return redirect(url_for("inventory", tab="categories"))


@app.route("/inventory/categories/<int:cid>/delete", methods=["POST"])
def category_delete(cid):
    db().execute("DELETE FROM categories WHERE id = ?", (cid,))
    db().commit()
    flash("Category deleted. Products stay, they just lose the category.", "ok")
    return redirect(url_for("inventory", tab="categories"))


def active_products():
    return db().execute("""SELECT id, name, price, qty, sku, brand, model FROM products
                           WHERE active = 1 ORDER BY name""").fetchall()


def parse_set_components(form):
    ids = form.getlist("component_id")
    qtys = form.getlist("component_qty")
    picked = {}
    for pid_raw, qty_raw in zip(ids, qtys):
        pid = to_int(pid_raw)
        if pid is None:
            continue
        qty = to_int(qty_raw) or 1
        if qty <= 0:
            continue
        picked[pid] = picked.get(pid, 0) + qty
    return list(picked.items())


def validate_set_components(components):
    if not components:
        return "A set needs at least one product component."
    rows = db().execute("""SELECT id FROM products WHERE active = 1
                           AND id IN (%s)""" % ",".join("?" * len(components)),
                        tuple(pid for pid, _ in components)).fetchall()
    if len(rows) != len(components):
        return "Every component must be an active product."
    return None


def render_set_form(stored, products, action_url, submit_label):
    comps = {}
    if stored:
        for c in stored.get("components") or []:
            comps[c["product_id"] if "product_id" in c else c["id"]] = c["qty"]
    return render_template("set_form.html", stored=stored or {}, products=products,
                           components=comps, action_url=action_url,
                           submit_label=submit_label)


def save_set_components(conn, sid, components):
    conn.execute("DELETE FROM set_products WHERE set_id = ?", (sid,))
    for pid, qty in components:
        conn.execute("INSERT INTO set_products (set_id, product_id, qty) VALUES (?, ?, ?)",
                     (sid, pid, qty))


@app.route("/inventory/sets/new", methods=["GET", "POST"])
def set_new():
    if request.method == "GET":
        return render_set_form(None, active_products(), url_for("set_new"), "Create set")
    name = (request.form.get("name") or "").strip()
    desc = (request.form.get("description") or "").strip()
    price = parse_amount(request.form.get("price"))
    comps = parse_set_components(request.form)
    err = None
    if not name:
        err = "Set name is required."
    elif price is not None and price < 0:
        err = "Set price cannot be negative."
    else:
        err = validate_set_components(comps)
    if err:
        flash(err, "error")
        return render_set_form({"name": name, "description": desc, "price": price,
                                "components": [{"product_id": pid, "qty": qty}
                                               for pid, qty in comps]},
                               active_products(), url_for("set_new"), "Create set")
    conn = db()
    try:
        cur = conn.execute("INSERT INTO sets (name, description, price, created_at)"
                           " VALUES (?, ?, ?, ?)", (name, desc or None, price, now_local()))
        sid = cur.lastrowid
        save_set_components(conn, sid, comps)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("That set name already exists.", "error")
        return render_set_form({"name": name, "description": desc, "price": price,
                                "components": [{"product_id": pid, "qty": qty}
                                               for pid, qty in comps]},
                               active_products(), url_for("set_new"), "Create set")
    flash(f"Set {name} created.", "ok")
    return redirect(url_for("inventory", tab="sets"))


@app.route("/inventory/sets/<int:sid>/edit", methods=["GET", "POST"])
def set_edit(sid):
    conn = db()
    s = conn.execute("SELECT * FROM sets WHERE id = ? AND active = 1", (sid,)).fetchone()
    if s is None:
        flash("Set not found.", "error")
        return redirect(url_for("inventory", tab="sets"))
    s = dict(s)
    s["components"] = [{"product_id": c["id"], "qty": c["per_set"], "name": c["name"]}
                       for c in set_components(conn, sid)]
    if request.method == "GET":
        return render_set_form(s, active_products(), url_for("set_edit", sid=sid), "Save set")
    name = (request.form.get("name") or s["name"]).strip()
    desc = (request.form.get("description") or "").strip()
    price = parse_amount(request.form.get("price"))
    comps = parse_set_components(request.form)
    err = None
    if not name:
        err = "Set name is required."
    elif price is not None and price < 0:
        err = "Set price cannot be negative."
    else:
        err = validate_set_components(comps)
    if err:
        flash(err, "error")
        s.update(name=name, description=desc, price=price,
                 components=[{"product_id": pid, "qty": qty} for pid, qty in comps])
        return render_set_form(s, active_products(), url_for("set_edit", sid=sid), "Save set")
    try:
        conn.execute("UPDATE sets SET name = ?, description = ?, price = ? WHERE id = ?",
                     (name, desc or None, price, sid))
        save_set_components(conn, sid, comps)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("That set name already exists.", "error")
        s.update(name=name, description=desc, price=price,
                 components=[{"product_id": pid, "qty": qty} for pid, qty in comps])
        return render_set_form(s, active_products(), url_for("set_edit", sid=sid), "Save set")
    flash(f"Set {name} updated.", "ok")
    return redirect(url_for("inventory", tab="sets"))


@app.route("/inventory/sets/<int:sid>/delete", methods=["POST"])
def set_delete(sid):
    conn = db()
    conn.execute("DELETE FROM set_products WHERE set_id = ?", (sid,))
    conn.execute("DELETE FROM sets WHERE id = ?", (sid,))
    conn.commit()
    flash("Set deleted.", "ok")
    return redirect(url_for("inventory", tab="sets"))


# --------------------------------------------------------------------- POS
def clean_phone(raw):
    """Digits (and a leading +) only - spaces/dashes/parens dropped."""
    raw = (raw or "").strip()
    keep = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    return keep[:20]


def clean_note(raw):
    return (raw or "").strip()[:300]


def customer_data():
    return session.get("customer") or {}


def save_customer(phone, note):
    phone, note = clean_phone(phone), clean_note(note)
    if phone or note:
        session["customer"] = {"phone": phone, "note": note}
    else:
        session.pop("customer", None)
    session.modified = True
    return {"phone": phone, "note": note}


def is_fx():
    """True when the caller asked for the cart fragment instead of a page reload."""
    return request.headers.get("X-FX") == "1"


def cart_context():
    """Everything the cart column needs - one place, reused by /pos and by the partial."""
    d = db()
    entries, goods_total = cart_entries()
    cart_sets, set_total = set_entries()
    goods_total = round(goods_total + set_total, 2)
    pays = payment_lines()
    total, paid, vat = pay_totals(d, pays, goods_total)
    held = d.execute("SELECT * FROM held_carts ORDER BY id DESC").fetchall()
    _, cart_errors, _, shortages = cart_requirements(entries, cart_sets)
    return dict(cart=entries, cart_sets=cart_sets, total=total, goods_total=goods_total,
                vat=vat, short={s["id"]: s for s in shortages}, cart_errors=cart_errors,
                pays=pays, paid=paid, balance=max(total - paid, 0), change=max(paid - total, 0),
                held=held, customer=customer_data(), surcharge=surcharge_total(pays),
                q=(request.values.get("q") or "").strip(),
                cat=to_int(request.values.get("cat")),
                browse=(request.values.get("browse") or "").strip() == "1",
                open_pay=(request.values.get("open") or "").strip() == "1",
                pay_methods=payment_rows(active_only=True),
                NOTE_KEYS=[r["key"] for r in payment_rows(active_only=True) if r["requires_note"]],
                pm_map=payment_map())


def cart_partial():
    # _cart_panel.html carries its own #cart-panel wrapper, so the fragment is exactly
    # one element and erpFx can swap outerHTML without a wrapper to unwrap.
    return render_template("_cart_panel.html", **cart_context())


def pos_redirect(include_open=False):
    q = (request.values.get("q") or "").strip()
    cat = (request.values.get("cat") or "").strip()
    args = {}
    if q:
        args["q"] = q
    if cat:
        args["cat"] = cat
    if (request.values.get("browse") or "").strip():
        args["browse"] = "1"
    if include_open:
        args["open"] = "1"
    if is_fx():
        return cart_partial()
    return redirect(url_for("pos", **args))


def cart_entries():
    cart = session.get("cart", {})
    entries = []
    clean = {}
    for pid, qty in cart.items():
        pid_i, qty_i = to_int(pid), to_int(qty)
        if pid_i is None or qty_i is None or qty_i <= 0:
            continue                                  # junk written into the session
        clean[str(pid_i)] = min(qty_i, MAX_QTY_PER_LINE)
    # one round trip for the whole cart, not one per line (each is a Turso request)
    found = {}
    if clean:
        marks = ",".join("?" for _ in clean)
        found = {r["id"]: r for r in db().execute(
            f"SELECT * FROM products WHERE active = 1 AND id IN ({marks})",
            tuple(int(k) for k in clean)).fetchall()}
    for key, qty_i in clean.items():
        p = found.get(int(key))
        if p is None:
            continue                                  # deleted or retired since it was added
        row = dict(p)
        row["qty"] = max(0, row["qty"])
        entries.append((row, qty_i))
    if clean != cart:
        session["cart"] = clean
    entries.sort(key=lambda e: e[0]["name"])
    total = round(sum(p["price"] * q for p, q in entries), 2)
    return entries, total


def set_components(conn, sid):
    return [dict(r) for r in conn.execute(
        """SELECT p.id, p.name, p.price, p.qty AS stock, sp.qty AS per_set,
                  p.category_id AS category_id
           FROM set_products sp
           JOIN products p ON p.id = sp.product_id
           WHERE sp.set_id = ? AND p.active = 1
           ORDER BY p.name""", (sid,)).fetchall()]


def missing_set_components(conn, sid):
    """Components whose product was deleted (or purged) - the set cannot be sold as-is."""
    out = []
    for r in conn.execute("""SELECT sp.product_id, p.name, p.active FROM set_products sp
                            LEFT JOIN products p ON p.id = sp.product_id
                            WHERE sp.set_id = ?""", (sid,)).fetchall():
        if r["name"] is None:
            out.append(f"product id {r['product_id']} (purged)")
        elif not r["active"]:
            out.append(f"{r['name']} (deleted)")
    return out


def set_price_of(s, comps):
    base = round(sum(c["price"] * c["per_set"] for c in comps), 2)
    if s.get("price") is not None:
        return round(float(s["price"]), 2), base
    return base, base


def set_entries():
    conn = db()
    out = []
    total = 0.0
    wanted = {}
    for sid, qty in list(session.get("sets", {}).items()):
        sid_i, qty_i = to_int(sid), to_int(qty)
        if sid_i is not None and qty_i is not None and qty_i > 0:
            wanted[sid_i] = qty_i
    if not wanted:
        return out, 0.0
    # two round trips for every set in the cart instead of two per set
    marks = ",".join("?" for _ in wanted)
    found = {r["id"]: r for r in conn.execute(
        f"SELECT * FROM sets WHERE active = 1 AND id IN ({marks})", tuple(wanted)).fetchall()}
    comps_by_set = {}
    for r in conn.execute(
            f"""SELECT sp.set_id, p.id, p.name, p.price, p.qty AS stock, sp.qty AS per_set,
                       p.category_id AS category_id
                FROM set_products sp JOIN products p ON p.id = sp.product_id
                WHERE sp.set_id IN ({marks}) AND p.active = 1
                ORDER BY p.name""", tuple(wanted)).fetchall():
        c = dict(r)
        comps_by_set.setdefault(c.pop("set_id"), []).append(c)
    for sid, qty in wanted.items():
        s = found.get(sid)
        if s is None:
            continue
        comps = comps_by_set.get(sid, [])
        s = dict(s)
        s["unit_price"], s["base_price"] = set_price_of(s, comps)
        s["components"] = comps
        out.append((s, qty))
        total += s["unit_price"] * qty
    out.sort(key=lambda e: e[0]["name"])
    return out, round(total, 2)


def cart_requirements(product_entries=None, cart_sets=None):
    if product_entries is None:
        product_entries, _ = cart_entries()
    if cart_sets is None:
        cart_sets, _ = set_entries()
    conn = db()
    need = {}
    for p, qty in product_entries:
        need[p["id"]] = need.get(p["id"], 0) + qty
    for s, qty in cart_sets:
        for c in s["components"]:
            need[c["id"]] = need.get(c["id"], 0) + qty * c["per_set"]
    errors = []
    remaining = {}
    short = []
    if need:
        marks = ",".join("?" for _ in need)
        found = {r["id"]: r for r in conn.execute(
            f"SELECT id, name, qty FROM products WHERE active = 1 AND id IN ({marks})",
            tuple(need)).fetchall()}
    else:
        found = {}
    for pid, req in need.items():
        p = found.get(pid)
        if p is None:
            errors.append(f"Cart item references product id {pid}, which is unavailable.")
            continue
        remaining[pid] = max(p["qty"] - req, 0)
        if req > p["qty"]:
            short.append({"id": pid, "name": p["name"], "need": req,
                          "stock": p["qty"], "missing": req - p["qty"]})
    return need, errors, remaining, short


def cart_goods_total(product_entries=None, cart_sets=None):
    if product_entries is None:
        product_entries, prod_total = cart_entries()
    else:
        prod_total = round(sum(p["price"] * q for p, q in product_entries), 2)
    if cart_sets is None:
        cart_sets, set_total = set_entries()
    else:
        set_total = round(sum(s["unit_price"] * q for s, q in cart_sets), 2)
    return round(prod_total + set_total, 2)


def set_catalog(q="", cat_id=None):
    conn = db()
    products = [dict(r) for r in conn.execute(
        "SELECT id, name FROM products WHERE active = 1 ORDER BY name").fetchall()]
    sets = [dict(r) for r in conn.execute(
        """SELECT s.* FROM sets s WHERE s.active = 1 ORDER BY s.name""").fetchall()]
    wanted = query_words(q)
    need, _, _, _ = cart_requirements()      # once, not once per set
    # Two queries for every set instead of two queries per set.
    comps_by_set, missing_by_set = {}, {}
    for r in conn.execute("""SELECT sp.set_id, p.id, p.name, p.price, p.qty AS stock,
                                   sp.qty AS per_set, p.category_id AS category_id
                            FROM set_products sp
                            JOIN products p ON p.id = sp.product_id AND p.active = 1
                            ORDER BY p.name""").fetchall():
        comps_by_set.setdefault(r["set_id"], []).append(dict(r))
    for r in conn.execute("""SELECT sp.set_id, sp.product_id, p.name, p.active
                            FROM set_products sp
                            LEFT JOIN products p ON p.id = sp.product_id""").fetchall():
        if r["name"] is None:
            missing_by_set.setdefault(r["set_id"], []).append(f"product id {r['product_id']} (purged)")
        elif not r["active"]:
            missing_by_set.setdefault(r["set_id"], []).append(f"{r['name']} (deleted)")
    out = []
    for s in sets:
        comps = comps_by_set.get(s["id"], [])
        missing = missing_by_set.get(s["id"], [])
        if cat_id is not None and not any(c.get("category_id") == cat_id for c in comps):
            continue
        price, base = set_price_of(s, comps)
        if wanted:
            # same rule the browse box uses: every word must appear somewhere
            hay = norm(" ".join([s.get("name") or "", s.get("description") or ""]
                                + [c["name"] or "" for c in comps]
                                + [s.get("sku") or "", s.get("brand") or ""]))
            if not all(norm(w) in hay for w in wanted):
                continue
        max_add = 9999
        for c in comps:
            max_add = min(max_add, (c["stock"] - need.get(c["id"], 0)) // max(c["per_set"], 1))
        s.update(components=comps, unit_price=price, base_price=base,
                 available=0 if missing else max(0, max_add), component_count=len(comps),
                 short=[c["name"] for c in comps
                        if c["stock"] - need.get(c["id"], 0) < c["per_set"]] + missing,
                 missing=missing)
        out.append(s)
    return out, products


def add_set_to_cart(sid, qty=1):
    conn = db()
    s = conn.execute("SELECT * FROM sets WHERE id = ? AND active = 1", (sid,)).fetchone()
    if s is None:
        return "Set not found."
    comps = set_components(conn, sid)
    if not comps:
        return f"{s['name']} has no components."
    missing = missing_set_components(conn, sid)
    if missing:
        return f"{s['name']} cannot be sold - component missing: {', '.join(missing)}."
    cart_sets = session.get("sets", {})
    key = str(sid)
    cart_sets[key] = cart_sets.get(key, 0) + qty
    session["sets"] = cart_sets
    return None


def payment_lines():
    return session.get("payments", [])


@app.route("/")
@app.route("/pos")
def pos():
    q = request.args.get("q", "").strip()
    cat_id = to_int(request.args.get("cat"))
    d = db()
    sql = """SELECT p.*, c.name AS category FROM products p
             LEFT JOIN categories c ON c.id = p.category_id
             WHERE p.active = 1"""
    args = []
    if q:
        clause, extra = all_words(product_columns(), q)
        if clause:
            sql += f" AND {clause}"
            args += extra
    if cat_id is not None:
        sql += " AND p.category_id = ?"
        args.append(cat_id)
    sql += " ORDER BY (p.qty <= 0), p.name"
    products = d.execute(sql, args).fetchall()

    sold_out = d.execute("""SELECT p.name FROM products p
                            WHERE p.active = 1 AND p.qty <= 0 ORDER BY p.name""").fetchall()
    chips = d.execute("""SELECT c.id, c.name,
                         COALESCE((SELECT SUM(p.qty) FROM products p
                                   WHERE p.active = 1 AND p.category_id = c.id), 0) AS stock
                         FROM categories c ORDER BY c.name""").fetchall()

    entries, goods_total = cart_entries()
    cart_sets, set_total = set_entries()
    goods_total = round(goods_total + set_total, 2)
    pays = payment_lines()
    total, paid, vat = pay_totals(d, pays, goods_total)
    held = d.execute("SELECT * FROM held_carts ORDER BY id DESC").fetchall()
    sets_for_pos, _ = set_catalog(q, cat_id)
    _, cart_errors, _, shortages = cart_requirements(entries, cart_sets)
    short_by_id = {s["id"]: s for s in shortages}
    browse = request.args.get("browse") == "1"
    browse_title = "All products"
    if cat_id is not None:
        crow = d.execute("SELECT name FROM categories WHERE id = ?", (cat_id,)).fetchone()
        browse_title = crow["name"] if crow else "All products"
    return render_template("pos.html", products=products, cart=entries, total=total,
                           goods_total=goods_total, vat=vat, sets=sets_for_pos,
                           cart_sets=cart_sets, short=short_by_id,
                           cart_errors=cart_errors, browse=browse,
                           browse_title=browse_title, browse_products=products,
                           browse_sets=sets_for_pos,
                           sold_out=[r["name"] for r in sold_out], q=q, cat=cat_id,
                           pays=pays, paid=paid, balance=max(total - paid, 0),
                           change=max(paid - total, 0), categories=chips, held=held,
                           customer=customer_data(), surcharge=surcharge_total(pays),
                           surcharge_rates={r["key"]: r["commission_percent"]
                                            for r in payment_rows(active_only=True)
                                            if r["commission_mode"] == "SURCHARGE"
                                            and r["commission_percent"]},
                           open_pay=request.args.get("open") == "1",
                           pay_methods=payment_rows(active_only=True),
                           NOTE_KEYS=[r["key"] for r in payment_rows(active_only=True)
                                      if r["requires_note"]],
                           pm_map=payment_map())


@app.route("/pos/search")
def pos_search():
    """Live autocomplete: matches name, SKU, barcode and brand at the same time."""
    q = (request.args.get("q") or "").strip()
    cat_id = to_int(request.args.get("cat"))
    sql = """SELECT p.id, p.name, p.price, p.qty, IFNULL(p.sku,'') AS sku,
                    IFNULL(p.barcode,'') AS barcode, c.name AS category
             FROM products p LEFT JOIN categories c ON c.id = p.category_id
             WHERE p.active = 1"""
    args = []
    if q:
        clause, extra = all_words(product_columns(), q)
        if clause:
            sql += f" AND {clause}"
            args += extra
    if cat_id is not None:
        sql += " AND p.category_id = ?"
        args.append(cat_id)
    lim = min(max(to_int(request.args.get("limit")) or 8, 1), 200)
    sql += " ORDER BY (p.qty <= 0), p.name LIMIT ?"
    args.append(lim)
    out = []
    for r in db().execute(sql, args).fetchall():
        out.append({
            "id": r["id"], "name": r["name"], "price": money(r["price"]),
            "price_num": float(r["price"]), "amount": float(r["price"]), "qty": r["qty"],
            "code": r["barcode"] or r["sku"], "category": r["category"] or "",
        })
    return jsonify(out)


@app.route("/pos/scan", methods=["POST"])
def pos_scan():
    value = (request.form.get("barcode") or "").strip()
    if not value:
        flash("Scan a barcode or type a SKU.", "error")
        return pos_redirect()
    rows = db().execute("""SELECT * FROM products WHERE active = 1
                           AND (n_barcode = ? OR n_sku = ?)
                           ORDER BY name""", (norm(value), norm(value))).fetchall()
    if not rows:
        flash(f"Barcode scan “{value}” - no product matches.", "error")
    elif len(rows) > 1:
        names = "; ".join(f"{r['name']} ({r['barcode'] or r['sku'] or '-'}, {r['qty']} in stock)"
                          for r in rows)
        flash(f"Barcode “{value}” matches several products: {names}. Search and pick one.",
              "error")
    else:
        row = rows[0]
        if row["qty"] <= 0:
            flash(f"{row['name']} has no stock.", "error")
        else:
            err = add_to_cart(row["id"], row["name"], row["qty"])
            if err:
                flash(err, "error")
            else:
                flash(f"Scanned {row['name']} - {money(row['price'])}.", "ok")
    return pos_redirect()


def add_to_cart(pid, name, qty_available=None):
    cart = session.get("cart", {})
    key = str(pid)
    if key not in cart and len(cart) >= MAX_CART_LINES:
        return f"Cart already holds {MAX_CART_LINES} different items - sell or clear some first."
    cart[key] = cart.get(key, 0) + 1
    session["cart"] = cart
    return None


@app.route("/pos/add/<int:pid>", methods=["POST"])
def pos_add(pid):
    p = db().execute("SELECT * FROM products WHERE id = ? AND active = 1", (pid,)).fetchone()
    if p is None:
        flash("Product not found.", "error")
    else:
        err = add_to_cart(pid, p["name"], p["qty"])
        if err:
            flash(err, "error")
    return pos_redirect()


@app.route("/pos/add/set/<int:sid>", methods=["POST"])
def pos_add_set(sid):
    s = db().execute("SELECT name FROM sets WHERE id = ? AND active = 1", (sid,)).fetchone()
    err = add_set_to_cart(sid)
    if err:
        flash(err, "error")
    else:
        flash(f"Added set {s['name']} to cart.", "ok")
    return pos_redirect()


@app.route("/pos/add/set/<int:sid>/items", methods=["POST"])
def pos_add_set_items(sid):
    """Load a set's component products into the cart (not a single "set" line)."""
    conn = db()
    s = conn.execute("SELECT * FROM sets WHERE id = ? AND active = 1", (sid,)).fetchone()
    if s is None:
        flash("Set not found.", "error")
        return pos_redirect()
    missing = missing_set_components(conn, sid)
    if missing:
        flash(f"{s['name']} cannot be added - component missing: {', '.join(missing)}.", "error")
        return pos_redirect()
    need, _, _, _ = cart_requirements()
    added, blocked = [], []
    for c in set_components(conn, sid):
        placed = 0
        for _ in range(max(c["per_set"], 1)):
            if need.get(c["id"], 0) + 1 > c["stock"]:
                break
            add_to_cart(c["id"], c["name"], c["stock"])
            need[c["id"]] = need.get(c["id"], 0) + 1
            placed += 1
        if placed == c["per_set"]:
            added.append(f"{c['name']} x{placed}")
        else:
            blocked.append(f"{c['name']} (need {c['per_set']}, only {c['stock']} in stock)")
    if added:
        flash(f"{s['name']} loaded: " + ", ".join(added) + ".", "ok")
    if blocked:
        flash(f"{s['name']} - not enough stock: " + ", ".join(blocked) + ".", "error")
    return pos_redirect()


@app.route("/pos/dec/set/<int:sid>", methods=["POST"])
def pos_dec_set(sid):
    cart_sets = session.get("sets", {})
    key = str(sid)
    if cart_sets.get(key, 0) <= 1:
        cart_sets.pop(key, None)
    else:
        cart_sets[key] -= 1
    session["sets"] = cart_sets
    return pos_redirect()


@app.route("/pos/remove/set/<int:sid>", methods=["POST"])
def pos_remove_set(sid):
    cart_sets = session.get("sets", {})
    cart_sets.pop(str(sid), None)
    session["sets"] = cart_sets
    return pos_redirect()


@app.route("/pos/dec/<int:pid>", methods=["POST"])
def pos_dec(pid):
    cart = session.get("cart", {})
    key = str(pid)
    if cart.get(key, 0) <= 1:
        cart.pop(key, None)
    else:
        cart[key] -= 1
    session["cart"] = cart
    return pos_redirect()


@app.route("/pos/remove/<int:pid>", methods=["POST"])
def pos_remove(pid):
    cart = session.get("cart", {})
    cart.pop(str(pid), None)
    session["cart"] = cart
    return pos_redirect()


@app.route("/pos/clear", methods=["POST"])
def pos_clear():
    session["cart"] = {}
    session["sets"] = {}
    session["payments"] = []
    return pos_redirect()


# held carts -----------------------------------------------------------------
@app.route("/pos/hold", methods=["POST"])
def pos_hold():
    cart = session.get("cart", {})
    cart_sets = session.get("sets", {})
    pays = payment_lines()
    if not cart and not cart_sets and not pays:
        flash("Nothing to hold - cart is empty.", "error")
        return pos_redirect()
    label = (request.form.get("label") or "").strip() or "Held cart"
    # v travels with the blob: a held cart written by an older build is recognisable
    # at resume time instead of being merged into a cart shaped differently.
    data = json.dumps({"v": HELD_SCHEMA, "cart": cart, "sets": cart_sets, "payments": pays})
    db().execute("INSERT INTO held_carts (label, data, created_at) VALUES (?, ?, ?)",
                 (label, data, now_local()))
    db().commit()
    session["cart"] = {}
    session["sets"] = {}
    session["payments"] = []
    flash(f"Cart held: {label}.", "ok")
    return pos_redirect()


@app.route("/pos/hold/<int:hid>/resume", methods=["POST"])
def pos_hold_resume(hid):
    row = db().execute("SELECT * FROM held_carts WHERE id = ?", (hid,)).fetchone()
    if row is None:
        flash("Held cart not found.", "error")
        return pos_redirect()
    try:
        data = json.loads(row["data"])
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict) or data.get("v", HELD_SCHEMA) != HELD_SCHEMA:
        # A blob from another build is left where it is rather than half-merged.
        version = data.get("v", "unset") if isinstance(data, dict) else "unreadable"
        flash(f"Held cart '{row['label']}' was written by an older version "
              f"(v{version}) - delete it and rebuild the cart.", "error")
        return pos_redirect()
    cart = session.get("cart", {})
    cart_blob = data.get("cart") if isinstance(data.get("cart"), dict) else {}
    sets_blob = data.get("sets") if isinstance(data.get("sets"), dict) else {}
    for pid, qty in cart_blob.items():
        pid_i, qty_i = to_int(pid), to_int(qty)
        if pid_i is None or not qty_i:
            continue
        cart[str(pid_i)] = min(cart.get(str(pid_i), 0) + qty_i, MAX_QTY_PER_LINE)
    cart_sets = session.get("sets", {})
    for sid, qty in sets_blob.items():
        sid_i, qty_i = to_int(sid), to_int(qty)
        if sid_i is None or not qty_i:
            continue
        cart_sets[str(sid_i)] = min(cart_sets.get(str(sid_i), 0) + qty_i, MAX_QTY_PER_LINE)
    session["cart"] = cart
    session["sets"] = cart_sets
    methods = payment_map()
    kept = []
    for pay in data.get("payments") or []:
        # only well-formed lines for a method that still exists; anything else would
        # crash the totals later
        if not isinstance(pay, dict) or pay.get("method") not in methods:
            continue
        try:
            amount = round(float(pay.get("amount")), 2)
        except (TypeError, ValueError):
            continue
        if amount > 0 and amount == amount:          # rejects NaN too
            kept.append({"method": pay["method"], "amount": amount,
                         "note": clean_pay_note(pay.get("note"))})
    session["payments"] = payment_lines() + kept
    db().execute("DELETE FROM held_carts WHERE id = ?", (hid,))
    db().commit()
    flash(f"Resumed held cart: {row['label']}.", "ok")
    return pos_redirect()


@app.route("/pos/hold/<int:hid>/delete", methods=["POST"])
def pos_hold_delete(hid):
    db().execute("DELETE FROM held_carts WHERE id = ?", (hid,))
    db().commit()
    flash("Held cart deleted.", "ok")
    return pos_redirect()


# payment split lines -------------------------------------------------------
def valid_method(method):
    rows = {r["key"]: dict(r) for r in payment_rows(active_only=True)}
    return rows.get(method)


def clean_pay_note(raw):
    return (raw or "").strip()[:300]


def note_required(pm):
    return bool(pm and pm.get("requires_note"))


def pay_note_error(pm, raw):
    """Error text when a method demands a note (e.g. Leasing) and none was typed."""
    if note_required(pm) and not clean_pay_note(raw):
        return (f"{pm['label']} payment needs a note - type which leasing app or "
                "provider the client used.")
    return None


def note_of(pm, raw):
    return clean_pay_note(raw) if note_required(pm) else ""


AMOUNT_RE = re.compile(r"(?:\d+|\d*\.\d{1,2})\Z")


def parse_amount(raw):
    """Digits with at most one decimal point - '1.2.3' and '12,,000' are rejected, not bent."""
    raw = (raw or "").strip().replace(",", "").replace(CURRENCY, "")
    if not AMOUNT_RE.match(raw):
        return None
    # Amounts are stored as REAL. Rounding to whole cents on the way in keeps every
    # stored value exact enough that sums never drift (tugrik prices are whole anyway).
    return round(float(raw), 2)


@app.route("/pos/pay", methods=["POST"])
def pos_pay():
    pm = valid_method(request.form.get("method", ""))
    if pm is None:
        flash("Pick a valid payment method.", "error")
        return pos_redirect(True)
    amount = parse_amount(request.form.get("amount"))
    if amount is None or amount <= 0:
        flash("Payment amount must be greater than zero.", "error")
        return pos_redirect(True)
    err = pay_note_error(pm, request.form.get("note"))
    if err:
        flash(err, "error")
        return pos_redirect(True)
    pays = payment_lines()
    pays.append({"method": pm["key"], "amount": round(amount, 2),
                 "note": note_of(pm, request.form.get("note"))})
    session["payments"] = pays
    return pos_redirect(True)


@app.route("/pos/pay/exact", methods=["POST"])
def pos_pay_exact():
    pm = valid_method(request.form.get("method", ""))
    if pm is None:
        flash("Pick a valid payment method.", "error")
        return pos_redirect(True)
    err = pay_note_error(pm, request.form.get("note"))
    if err:
        flash(err, "error")
        return pos_redirect(True)
    goods_total = cart_goods_total()
    pays = payment_lines()
    total, paid, _ = pay_totals(db(), pays, goods_total)
    remaining = round(total - paid, 2)
    if remaining <= 0.004:
        flash("Already fully paid.", "ok")
    else:
        pays.append({"method": pm["key"], "amount": remaining,
                     "note": note_of(pm, request.form.get("note"))})
        session["payments"] = pays
    return pos_redirect(True)


@app.route("/pos/pay/remove/<int:idx>", methods=["POST"])
def pos_pay_remove(idx):
    pays = payment_lines()
    if 0 <= idx < len(pays):
        pays.pop(idx)
    session["payments"] = pays
    return pos_redirect(True)


@app.route("/pos/pay/clear", methods=["POST"])
def pos_pay_clear():
    session["payments"] = []
    return pos_redirect(True)


@app.route("/pos/vat", methods=["POST"])
def pos_vat():
    session["vat"] = bool(request.form.get("vat"))
    goods_total = cart_goods_total()
    if request.headers.get("X-Requested-With") == "xhr":
        return jsonify(pay_state(payment_lines(), goods_total))
    return pos_redirect(True)


@app.route("/pos/customer", methods=["POST"])
def pos_customer():
    cust = save_customer(request.form.get("customer_phone"),
                         request.form.get("customer_note"))
    if request.headers.get("X-Requested-With") == "xhr":
        return jsonify({"ok": True, "customer": cust})
    return pos_redirect(True)


def pay_state(pays, goods_total):
    pm = payment_map()
    total, paid, vat = pay_totals(db(), pays, goods_total)
    lines = []
    for i, p in enumerate(pays):
        m = pm.get(p["method"])
        percent = (m or {}).get("commission_percent") or 0
        mode = (m or {}).get("commission_mode")
        fee = surcharge_of(m, p["amount"]) or absorbed_of(m, p["amount"])
        note = clean_pay_note(p.get("note"))
        needs_note = note_required(m) and not note
        lines.append({"idx": i, "method": p["method"],
                      "label": (m or {}).get("label", p["method"]),
                      "amount": round(p["amount"], 2), "fee": round(fee, 2),
                      "mode": mode if fee else None, "percent": percent,
                      "note": note, "needs_note": needs_note,
                      "api": f"/pos/api/pay/remove/{i}"})
    missing_note = any(l["needs_note"] for l in lines)
    return {"ok": True, "goods": round(goods_total, 2), "vat": vat, "total": total,
            "surcharge": surcharge_total(pays),
            "paid": paid, "balance": max(round(total - paid, 2), 0.0),
            "change": max(round(paid - total, 2), 0.0), "lines": lines,
            "can_complete": bool(pays) and (total - paid) <= 0.004 and not missing_note}


@app.route("/pos/api/pay", methods=["POST"])
def pos_api_pay():
    pm = valid_method(request.form.get("method", ""))
    if pm is None:
        return jsonify(ok=False, error="Pick a valid payment method.")
    amount = parse_amount(request.form.get("amount"))
    if amount is None or amount <= 0:
        return jsonify(ok=False, error="Payment amount must be greater than zero.")
    err = pay_note_error(pm, request.form.get("note"))
    if err:
        return jsonify(ok=False, error=err)
    pays = payment_lines()
    pays.append({"method": pm["key"], "amount": round(amount, 2),
                 "note": note_of(pm, request.form.get("note"))})
    session["payments"] = pays
    goods_total = cart_goods_total()
    return jsonify(pay_state(pays, goods_total))


@app.route("/pos/api/pay/exact", methods=["POST"])
def pos_api_pay_exact():
    pm = valid_method(request.form.get("method", ""))
    if pm is None:
        return jsonify(ok=False, error="Pick a valid payment method.")
    err = pay_note_error(pm, request.form.get("note"))
    if err:
        return jsonify(ok=False, error=err)
    goods_total = cart_goods_total()
    pays = payment_lines()
    total, paid, _ = pay_totals(db(), pays, goods_total)
    remaining = round(total - paid, 2)
    if remaining <= 0.004:
        return jsonify(ok=False, error="Already fully paid.")
    pays.append({"method": pm["key"], "amount": remaining,
                 "note": note_of(pm, request.form.get("note"))})
    session["payments"] = pays
    return jsonify(pay_state(pays, goods_total))


@app.route("/pos/api/pay/remove/<int:idx>", methods=["POST"])
def pos_api_pay_remove(idx):
    pays = payment_lines()
    if 0 <= idx < len(pays):
        pays.pop(idx)
    session["payments"] = pays
    goods_total = cart_goods_total()
    return jsonify(pay_state(pays, goods_total))


def sold_out_culprit(conn, need, entries, cart_sets):
    """Name the line stock ran out from - the guard only says 'no'."""
    names = {p["id"]: p["name"] for p, _ in entries}
    for s, _ in cart_sets:
        for c in s["components"]:
            names.setdefault(c["id"], c["name"])
    ids = list(need)
    if not ids:
        return "an item"
    slots = ", ".join(["?"] * len(ids))
    stock = {r["id"]: r["qty"] for r in conn.execute(
        f"SELECT id, qty FROM products WHERE id IN ({slots})", tuple(ids)).fetchall()}
    for pid, qty in need.items():
        if stock.get(pid, -1) < qty:
            return names.get(pid, f"item {pid}")
    return "an item"


@app.route("/pos/checkout", methods=["POST"])
def pos_checkout():
    entries, goods_total = cart_entries()
    cart_sets, set_total = set_entries()
    goods_total = round(goods_total + set_total, 2)
    pays = payment_lines()
    if not entries and not cart_sets:
        flash("Cart is empty.", "error")
        return pos_redirect(True)
    if not pays:
        flash("Add at least one payment (cash, card, bank transfer...).", "error")
        return pos_redirect(True)
    total, paid, vat = pay_totals(db(), pays, goods_total)
    if paid + 0.004 < total:
        flash(f"Payments cover {money(paid)} of {money(total)} - "
              f"{money(total - paid)} still due.", "error")
        return pos_redirect(True)
    pm_all = payment_map()
    missing = [pm_all.get(p["method"], {}).get("label", p["method"])
               for p in pays
               if note_required(pm_all.get(p["method"]))
               and not clean_pay_note(p.get("note"))]
    if missing:
        flash("Add the required note for: " + ", ".join(sorted(set(missing)))
              + " - which leasing app or provider did the client use?", "error")
        return pos_redirect(True)
    need, cart_errors, _, shortages = cart_requirements(entries, cart_sets)
    gone = {s["id"]: missing_set_components(db(), s["id"]) for s, _ in cart_sets}
    broken = [f"{s['name']} - component missing: {', '.join(gone[s['id']])}"
              for s, _ in cart_sets if gone[s["id"]]]
    cart_errors += broken
    if cart_errors or shortages:
        if cart_errors:
            flash(" | ".join(cart_errors), "error")
        if shortages:
            flash("Cannot sell - out of stock: " + ", ".join(
                f"{s['name']} (needs {s['need']}, only {s['stock']} left)" for s in shortages),
                  "error")
        return pos_redirect(True)
    saved = customer_data()
    cust_phone = clean_phone(request.form.get("customer_phone")
                             if request.form.get("customer_phone") is not None
                             else saved.get("phone"))
    cust_note = clean_note(request.form.get("customer_note")
                          if request.form.get("customer_note") is not None
                          else saved.get("note"))
    conn = db()
    item_count = sum(q for _, q in entries) + sum(q for _, q in cart_sets)
    pm_map = payment_map()
    need_lines = list(need.items())
    who = actor()
    for attempt in range(3):
        # Sale id is chosen up front so the whole sale can travel in one script.
        sale_id = next_sale_id(conn)
        ref = f"SALE-{sale_id:05d}"
        stmts = checkout_statements(sale_id, ref, entries, cart_sets, need_lines, pays, pm_map,
                                    total, paid, vat, item_count, cust_phone, cust_note, who)
        try:
            conn.script(stmts)
            break
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            msg = str(exc)
            if "stock_guards" in msg:
                flash(f"Cannot complete the sale: {sold_out_culprit(db(), need, entries, cart_sets)} "
                      "was just sold out by another session. The cart is untouched - "
                      "re-check stock and try again.", "error")
            elif "sales" in msg and attempt < 2:
                continue                     # another till took this number - take the next one
            else:
                flash("Could not save the sale - the cart is untouched, try again.", "error")
            app.logger.warning("checkout aborted (sale %s): %s", ref, exc)
            return pos_redirect(True)
    session["cart"] = {}
    session["sets"] = {}
    session["payments"] = []
    session["vat"] = False
    session["customer"] = {}
    flash(f"Sale {ref} recorded - {money(total)}.", "ok")
    return redirect(url_for("receipt", sale_id=sale_id))


def next_sale_id(conn):
    """Never hand out a number twice - not even one whose sale was deleted by an
    older build. sqlite_sequence remembers the highest id AUTOINCREMENT ever saw."""
    seq = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'sales'").fetchone()
    top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM sales").fetchone()[0]
    return max(int(seq[0]) if seq else 0, int(top or 0)) + 1


def checkout_statements(sale_id, ref, entries, cart_sets, need_lines, pays, pm_map,
                        total, paid, vat, item_count, cust_phone, cust_note, who):
    """The whole sale as one script. Every value travels as a bound parameter."""
    stmts = []
    if need_lines:
        # One guard for the whole cart: it inserts a duplicate primary key the moment any
        # line cannot be covered by stock, which aborts the whole transaction.
        stmts.append((
            "WITH need(pid, qty) AS (VALUES " + ", ".join("(?, ?)" for _ in need_lines) + ") "
            "INSERT INTO stock_guards (id) SELECT 1 FROM need "
            "WHERE COALESCE((SELECT qty FROM products WHERE id = need.pid), -1) < need.qty",
            [v for pid, qty in need_lines for v in (pid, qty)]))
    stamp = now_local()
    stmts.append(("""INSERT INTO sales (id, ref, total, paid, change, item_count, vat_amount,
                                        customer_phone, customer_note, n_search, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (sale_id, ref, total, paid, max(paid - total, 0), item_count, vat,
                   cust_phone or None, cust_note or None, blob_of(ref, cust_phone, cust_note),
                   stamp)))
    stmts.append(("""INSERT INTO sale_items (sale_id, product_id, name, price, qty, line_total, n_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  [(sale_id, p["id"], p["name"], p["price"], qty,
                    round(p["price"] * qty, 2), norm(p["name"])) for p, qty in entries]))
    if cart_sets:
        stmts.append(("""INSERT INTO sale_items (sale_id, product_id, set_id, name, price, qty,
                                                 line_total, n_name)
                        VALUES (?, NULL, ?, ?, ?, ?, ?, ?)""",
                      [(sale_id, s["id"], s["name"], s["unit_price"], qty,
                        round(s["unit_price"] * qty, 2), norm(s["name"])) for s, qty in cart_sets]))
    stmts.append(("""INSERT INTO inventory_logs (product_id, old_qty, new_qty, delta, reason, actor,
                                                sale_id, created_at)
                    SELECT id, qty, qty - ?, ?, 'sale', ?, ?, ? FROM products WHERE id = ?""",
                  [(qty, -qty, who, sale_id, stamp, pid) for pid, qty in need_lines]))
    stmts.append(("UPDATE products SET qty = qty - ? WHERE id = ? AND qty >= ?",
                  [(qty, pid, qty) for pid, qty in need_lines]))
    pay_rows = []
    for pay in pays:
        pm = pm_map.get(pay["method"]) or {}
        note = clean_pay_note(pay.get("note"))
        pay_rows.append((sale_id, pay["method"], pay["amount"],
                         pm.get("commission_percent") or 0, pm.get("commission_mode"),
                         absorbed_of(pm, pay["amount"]) + surcharge_of(pm, pay["amount"]),
                         note or None, norm(note)))
    stmts.append(("""INSERT INTO payments (sale_id, method, amount, commission_percent,
                                          commission_mode, commission_amount, note, n_note)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", pay_rows))
    return stmts


# ------------------------------------------------------------------- sales
SALES_PAGE = int(os.environ.get("ERP_SALES_PAGE") or 100)


@app.route("/sales")
def sales():
    """One page of sales at a time; count and takings are summed in SQL over every
    match, so the page stays fast and the total stays right as history grows."""
    methods = {r["key"]: r["label"] for r in payment_rows()}
    q = request.args.get("q", "").strip()
    page = max(to_int(request.args.get("page")) or 1, 1)
    where, args = "1 = 1", []
    if q:
        head = ["sales.n_search"]
        clauses = []
        for word in query_words(q):
            clause, extra = match_any(head, word)
            like = like_terms(word)
            group = (clause
                     + " OR EXISTS (SELECT 1 FROM payments pn"
                     "             WHERE pn.sale_id = sales.id"
                     "               AND pn.n_note LIKE ? ESCAPE '\\')"
                     + " OR EXISTS (SELECT 1 FROM sale_items si"
                     "             WHERE si.sale_id = sales.id"
                     "               AND si.n_name LIKE ? ESCAPE '\\')")
            clauses.append(f"({group})")
            args += extra + [like, like]
        if clauses:
            where = " AND ".join(clauses)
    agg = db().execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN voided_at IS NULL THEN total END), 0) AS t"
        " FROM sales WHERE " + where, args).fetchone()
    count, total = agg["n"], agg["t"]
    pages = max((count + SALES_PAGE - 1) // SALES_PAGE, 1)
    page = min(page, pages)
    rows = [dict(r) for r in db().execute(
        "SELECT * FROM sales WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
        args + [SALES_PAGE, (page - 1) * SALES_PAGE]).fetchall()]
    split = {}
    if rows:
        slots = ",".join("?" for _ in rows)
        pays = db().execute(
            f"""SELECT sale_id, method, amount, commission_amount, commission_mode, note
                FROM payments WHERE sale_id IN ({slots}) ORDER BY id""",
            tuple(r["id"] for r in rows)).fetchall()
    else:
        pays = []
    for r in pays:
        label = methods.get(r["method"], r["method"])
        if r["commission_mode"] == "SURCHARGE" and r["commission_amount"]:
            label += f" (+{money(r['commission_amount'])} fee)"
        elif r["commission_mode"] == "ABSORBED" and r["commission_amount"]:
            label += f" ({money(r['commission_amount'])} absorbed)"
        entry = f"{label} {money(r['amount'])}"
        note = clean_pay_note(r["note"])
        if note:
            entry += f" [{note}]"
        split.setdefault(r["sale_id"], []).append(entry)
    for r in rows:
        r["split"] = ", ".join(split.get(r["id"], []))
    if (request.args.get("format") == "json" or
            request.headers.get("X-Requested-With") == "xhr"):
        return jsonify(q=q, total=round(total, 2), count=count, page=page, pages=pages, rows=[
            {"id": r["id"], "ref": r["ref"], "created_at": r["created_at"],
             "item_count": r["item_count"], "total": round(r["total"], 2),
             "split": r["split"], "customer_phone": r["customer_phone"],
             "customer_note": r["customer_note"], "voided": bool(r.get("voided_at"))}
            for r in rows
        ])
    return render_template("sales.html", sales=rows, total=total, q=q,
                           count=count, page=page, pages=pages)


@app.route("/sales/<int:sale_id>")
def receipt(sale_id):
    conn = db()
    sale = conn.execute("SELECT * FROM sales WHERE id = ?", (sale_id,)).fetchone()
    if sale is None:
        flash("Sale not found.", "error")
        return redirect(url_for("sales"))
    items = conn.execute("SELECT * FROM sale_items WHERE sale_id = ? ORDER BY id",
                         (sale_id,)).fetchall()
    pays = conn.execute("SELECT * FROM payments WHERE sale_id = ? ORDER BY id",
                        (sale_id,)).fetchall()
    methods = {r["key"]: dict(r) for r in payment_rows()}
    commission = round(sum(p["commission_amount"] or 0 for p in pays), 2)
    # what the customer was actually charged then, not today's method settings
    surcharge = round(sum(p["commission_amount"] or 0 for p in pays
                          if p["commission_mode"] == "SURCHARGE"), 2)
    return render_template("receipt.html", sale=sale, items=items, pays=pays,
                           commission=commission, surcharge=surcharge,
                           vat=sale["vat_amount"] or 0, methods=methods)


def stock_taken_by(conn, sale_id):
    """{product_id: qty} the sale actually took out of stock.

    The audit log is the truth: checkout writes one 'sale' row per product, sets
    already broken into their components at the quantities sold. Older builds
    deleted voided sales and reused their ids, so a 'sale voided' row may share
    this id - netting both reasons cancels those leftovers out.
    Sales older than the audit log fall back to their line items."""
    logged = conn.execute("""SELECT COUNT(*) FROM inventory_logs
                             WHERE sale_id = ? AND reason = 'sale'""", (sale_id,)).fetchone()[0]
    if logged:
        rows = conn.execute("""SELECT product_id, -SUM(delta) AS qty FROM inventory_logs
                               WHERE sale_id = ? AND reason IN ('sale', 'sale voided')
                                 AND product_id IS NOT NULL
                               GROUP BY product_id""", (sale_id,)).fetchall()
        return {r["product_id"]: r["qty"] for r in rows if r["qty"] > 0}
    taken = {}
    for it in conn.execute("SELECT product_id, set_id, qty FROM sale_items WHERE sale_id = ?",
                           (sale_id,)).fetchall():
        if it["product_id"] is not None:
            taken[it["product_id"]] = taken.get(it["product_id"], 0) + it["qty"]
        elif it["set_id"] is not None:
            for c in conn.execute("SELECT product_id, qty FROM set_products WHERE set_id = ?",
                                  (it["set_id"],)).fetchall():
                taken[c["product_id"]] = taken.get(c["product_id"], 0) + it["qty"] * c["qty"]
    return taken


@app.route("/sales/<int:sale_id>/void", methods=["POST"])
def sale_void(sale_id):
    """A void keeps the sale (marked voided, out of the totals) and returns its stock."""
    conn = db()
    sale = conn.execute("SELECT * FROM sales WHERE id = ?", (sale_id,)).fetchone()
    if sale is None:
        flash("Sale not found.", "error")
        return redirect(url_for("sales"))
    if sale["voided_at"]:
        flash(f"Sale {sale['ref']} was already voided.", "error")
        return redirect(url_for("receipt", sale_id=sale_id))
    taken = stock_taken_by(conn, sale_id)
    who = actor()
    stmts = [
        # Two admins voiding at once: the second hits the guard and changes nothing.
        ("INSERT INTO stock_guards (id) SELECT 1 FROM sales WHERE id = ? AND voided_at IS NOT NULL",
         (sale_id,)),
        ("UPDATE sales SET voided_at = ?, voided_by = ? WHERE id = ?", (now_local(), who, sale_id)),
    ]
    if taken:
        stmts.append((LOG_SQL, [log_params(pid, qty, "sale voided", sale_id, who)
                                for pid, qty in taken.items()]))
        stmts.append(("UPDATE products SET qty = qty + ? WHERE id = ?",
                      [(qty, pid) for pid, qty in taken.items()]))
    try:
        conn.script(stmts)
    except sqlite3.IntegrityError:
        flash(f"Sale {sale['ref']} was already voided.", "error")
        return redirect(url_for("receipt", sale_id=sale_id))
    flash(f"Sale {sale['ref']} voided and stock returned.", "ok")
    return redirect(url_for("receipt", sale_id=sale_id))


# -------------------------------------------------- template globals
@app.context_processor
def erp_globals():
    rows = payment_rows()
    return {"PAY_METHODS": {r["key"]: r["label"] for r in rows},
            "PAYMENT_METHODS": [dict(r) for r in rows]}


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("ERP_HOST", "127.0.0.1"),
            port=int(os.environ.get("ERP_PORT", "5000")), debug=DEBUG_MODE)
