"""Single-user ERP: POS main screen + Inventory with categories inside Inventory.

Run:  python3 app.py          -> http://127.0.0.1:5000
"""
import json
import os
import re
import sqlite3
from pathlib import Path

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("ERP_DB") or (BASE / "erp.db"))
CURRENCY = "₮"
VAT_PERCENT = 10.0


def money(value):
    """1900000 -> '1,900,000₮' ; 1900000.5 -> '1,900,000.50₮'"""
    value = value or 0
    if abs(value - round(value)) < 1e-9:
        return f"{int(round(value)):,}{CURRENCY}"
    return f"{value:,.2f}{CURRENCY}"


app = Flask(__name__)
app.secret_key = "single-user-dev-secret-change-me"
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

SCHEMA = """
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sku TEXT UNIQUE,
    name TEXT NOT NULL,
    cost REAL NOT NULL DEFAULT 0,
    price REAL NOT NULL DEFAULT 0,
    qty INTEGER NOT NULL DEFAULT 0,
    low_stock_at INTEGER NOT NULL DEFAULT 5,
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
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    amount REAL NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    qty INTEGER NOT NULL,
    line_total REAL NOT NULL
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
"""

PRODUCT_COLUMNS = [
    ("barcode", "TEXT"),
    ("brand", "TEXT"),
    ("model", "TEXT"),
    ("specifications", "TEXT"),
    ("category_id", "INTEGER REFERENCES categories(id) ON DELETE SET NULL"),
    ("supplier_id", "INTEGER REFERENCES suppliers(id) ON DELETE SET NULL"),
    ("active", "INTEGER NOT NULL DEFAULT 1"),
]
PAYMENT_COLUMNS = [
    ("commission_percent", "REAL NOT NULL DEFAULT 0"),
    ("commission_mode", "TEXT"),
    ("commission_amount", "REAL NOT NULL DEFAULT 0"),
    ("note", "TEXT"),
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


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # SQLite's LIKE/LOWER only fold ASCII, so Cyrillic searches silently fail by case.
        g.db.create_function("norm", 1, norm, deterministic=True)
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
    """(norm(col) LIKE ? OR ...) for one word across the given columns."""
    clause = " OR ".join(f"norm({c}) LIKE ? ESCAPE '\\'" for c in columns)
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
    return ["p.name", "IFNULL(p.sku,'')", "IFNULL(p.barcode,'')", "IFNULL(p.brand,'')"]


def add_columns(conn, table, columns):
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns:
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    add_columns(conn, "products", PRODUCT_COLUMNS)
    add_columns(conn, "payments", PAYMENT_COLUMNS)
    add_columns(conn, "sale_items", [("set_id", "INTEGER REFERENCES sets(id) ON DELETE SET NULL")])

    cols = {r[1] for r in conn.execute("PRAGMA table_info(sales)")}
    if "vat_amount" not in cols:
        conn.execute("ALTER TABLE sales ADD COLUMN vat_amount REAL NOT NULL DEFAULT 0")
    add_columns(conn, "sales", [("customer_phone", "TEXT"),
                                ("customer_note", "TEXT")])
    for name, decl in (("paid", "REAL NOT NULL DEFAULT 0"),
                       ("change", "REAL NOT NULL DEFAULT 0")):
        if name not in cols:
            conn.execute(f"ALTER TABLE sales ADD COLUMN {name} {decl}")
            conn.execute("UPDATE sales SET paid = total WHERE paid = 0")

    add_columns(conn, "payment_methods",
                [("requires_note", "INTEGER NOT NULL DEFAULT 0")])
    conn.executemany(
        "INSERT OR IGNORE INTO payment_methods"
        " (key, label, commission_percent, commission_mode, active, sort, requires_note)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)", PAYMENT_SEED)
    for r in conn.execute("SELECT key FROM payment_methods").fetchall():
        conn.execute("UPDATE payment_methods SET requires_note = ? WHERE key = ?",
                     (1 if r["key"] in NOTE_REQUIRED_KEYS else 0, r["key"]))
    conn.commit()
    conn.close()


def payment_rows(active_only=False):
    sql = "SELECT * FROM payment_methods"
    if active_only:
        sql += " WHERE active = 1"
    return db().execute(sql + " ORDER BY sort, id").fetchall()


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


def pay_totals(conn, pays, goods_total):
    vat = vat_of(goods_total)
    total = round(goods_total + vat, 2)
    paid = round(sum(p["amount"] for p in pays), 2)
    return total, paid, vat


def category_rows():
    return db().execute("""SELECT c.*, COUNT(p.id) AS product_count FROM categories c
                           LEFT JOIN products p ON p.category_id = c.id AND p.active = 1
                           GROUP BY c.id ORDER BY c.name""").fetchall()


def supplier_rows():
    return db().execute("""SELECT s.*, COUNT(p.id) AS product_count FROM suppliers s
                           LEFT JOIN products p ON p.supplier_id = s.id AND p.active = 1
                           GROUP BY s.id ORDER BY s.name""").fetchall()


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
    low_count = sum(1 for r in rows if r["qty"] <= r["low_stock_at"])

    return render_template("inventory.html", tab="products", products=rows, q=q,
                           cat_id=cat_id, low=low, low_count=low_count,
                           categories=categories, sort=sort, sdir=sdir)


@app.route("/inventory/deleted")
def inventory_deleted():
    return redirect(url_for("inventory", tab="deleted"))


def product_form_errors(form):
    name = (form.get("name") or "").strip()
    if not name:
        return "Name is required."
    try:
        cost = float(form.get("cost") or 0)
        price = float(form.get("price") or 0)
        qty = int(form.get("qty") or 0)
        low = int(form.get("low_stock_at") or 5)
    except ValueError:
        return "Cost, price and quantities must be numbers."
    if cost < 0 or price < 0 or qty < 0 or low < 0:
        return "Values cannot be negative."
    return None


def form_values(form):
    return ((form.get("sku") or "").strip() or None,
            (form.get("name") or "").strip(),
            float(form.get("cost") or 0),
            float(form.get("price") or 0),
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
            db().execute(
                """INSERT INTO products (sku, name, cost, price, qty, low_stock_at, barcode,
                                         brand, model, specifications, category_id, supplier_id, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""", values)
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
            db().execute(
                """UPDATE products SET sku=?, name=?, cost=?, price=?, qty=?, low_stock_at=?,
                       barcode=?, brand=?, model=?, specifications=?, category_id=?, supplier_id=?
                   WHERE id=?""", (*values, pid))
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
        if qty <= 0:
            flash("Quantity must be a positive whole number.", "error")
        elif direction == "out" and qty > p["qty"]:
            flash(f"Cannot remove {qty} - only {p['qty']} in stock.", "error")
        else:
            new_qty = p["qty"] + (qty if direction == "in" else -qty)
            d.execute("UPDATE products SET qty = ? WHERE id = ?", (new_qty, pid))
            d.commit()
            flash(f"Stock updated: {p['name']} now {new_qty}.", "ok")
            return redirect(url_for("inventory"))
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
            db().execute("INSERT INTO categories (name) VALUES (?)", (name,))
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
        cur = conn.execute("INSERT INTO sets (name, description, price) VALUES (?, ?, ?)",
                           (name, desc or None, price))
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
    return redirect(url_for("pos", **args))


def cart_entries():
    cart = session.get("cart", {})
    entries = []
    conn = db()
    for pid, qty in cart.items():
        p = conn.execute("SELECT * FROM products WHERE id = ? AND active = 1",
                         (int(pid),)).fetchone()
        if p is None or qty <= 0:
            continue
        row = dict(p)
        row["qty"] = max(0, row["qty"])
        entries.append((row, qty))
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
    for sid, qty in list(session.get("sets", {}).items()):
        try:
            sid = int(sid)
            qty = int(qty)
        except (TypeError, ValueError):
            continue
        if qty <= 0:
            continue
        s = conn.execute("SELECT * FROM sets WHERE id = ? AND active = 1", (sid,)).fetchone()
        if s is None:
            continue
        comps = set_components(conn, sid)
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
    for pid, req in need.items():
        p = conn.execute("SELECT id, name, qty FROM products WHERE id = ? AND active = 1",
                         (pid,)).fetchone()
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
    out = []
    for s in sets:
        comps = set_components(conn, s["id"])
        missing = missing_set_components(conn, s["id"])
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
        need, _, _, _ = cart_requirements()
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
                           customer=customer_data(),
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
                           AND (norm(IFNULL(barcode,'')) = norm(?)
                                OR norm(IFNULL(sku,'')) = norm(?))
                           ORDER BY name""", (value, value)).fetchall()
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
    data = json.dumps({"cart": cart, "sets": cart_sets, "payments": pays})
    db().execute("INSERT INTO held_carts (label, data) VALUES (?, ?)", (label, data))
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
    cart = session.get("cart", {})
    for pid, qty in (data.get("cart") or {}).items():
        cart[str(pid)] = cart.get(str(pid), 0) + int(qty)
    cart_sets = session.get("sets", {})
    for sid, qty in (data.get("sets") or {}).items():
        cart_sets[str(sid)] = cart_sets.get(str(sid), 0) + int(qty)
    session["cart"] = cart
    session["sets"] = cart_sets
    session["payments"] = payment_lines() + list(data.get("payments") or [])
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


def parse_amount(raw):
    raw = (raw or "").strip().replace(",", "").replace(CURRENCY, "")
    try:
        return float(raw)
    except ValueError:
        return None


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
    broken = [f"{s['name']} - component missing: {', '.join(missing_set_components(db(), s['id']))}"
              for s, _ in cart_sets if missing_set_components(db(), s["id"])]
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
    cur = conn.execute(
        """INSERT INTO sales (ref, total, paid, change, item_count, vat_amount,
                              customer_phone, customer_note)
           VALUES ('', ?, ?, ?, ?, ?, ?, ?)""",
        (total, paid, max(paid - total, 0), item_count, vat,
         cust_phone or None, cust_note or None))
    sale_id = cur.lastrowid
    ref = f"SALE-{sale_id:05d}"
    conn.execute("UPDATE sales SET ref = ? WHERE id = ?", (ref, sale_id))
    pm_map = payment_map()
    for p, qty in entries:
        conn.execute(
            "INSERT INTO sale_items (sale_id, product_id, name, price, qty, line_total)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (sale_id, p["id"], p["name"], p["price"], qty, p["price"] * qty))
    for s, qty in cart_sets:
        conn.execute(
            """INSERT INTO sale_items (sale_id, product_id, set_id, name, price, qty, line_total)
               VALUES (?, NULL, ?, ?, ?, ?, ?)""",
            (sale_id, s["id"], s["name"], s["unit_price"], qty, s["unit_price"] * qty))
    for pid, qty in need.items():
        conn.execute("UPDATE products SET qty = qty - ? WHERE id = ?", (qty, pid))
    for pay in pays:
        pm = pm_map.get(pay["method"]) or {}
        conn.execute(
            """INSERT INTO payments (sale_id, method, amount, commission_percent,
                                     commission_mode, commission_amount, note)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sale_id, pay["method"], pay["amount"], pm.get("commission_percent") or 0,
             pm.get("commission_mode"), absorbed_of(pm, pay["amount"]) + surcharge_of(pm, pay["amount"]),
             clean_pay_note(pay.get("note")) or None))
    conn.commit()
    session["cart"] = {}
    session["sets"] = {}
    session["payments"] = []
    session["vat"] = False
    session["customer"] = {}
    flash(f"Sale {ref} recorded - {money(total)}.", "ok")
    return redirect(url_for("receipt", sale_id=sale_id))


# ------------------------------------------------------------------- sales
@app.route("/sales")
def sales():
    methods = {r["key"]: r["label"] for r in payment_rows()}
    q = request.args.get("q", "").strip()
    if q:
        head = ["sales.ref", "IFNULL(sales.customer_phone,'')", "IFNULL(sales.customer_note,'')"]
        clauses, args = [], []
        for word in query_words(q):
            clause, extra = match_any(head, word)
            like = like_terms(word)
            group = (clause
                     + " OR EXISTS (SELECT 1 FROM payments pn"
                     "             WHERE pn.sale_id = sales.id"
                     "               AND norm(IFNULL(pn.note,'')) LIKE ? ESCAPE '\\')"
                     + " OR EXISTS (SELECT 1 FROM sale_items si"
                     "             WHERE si.sale_id = sales.id"
                     "               AND norm(IFNULL(si.name,'')) LIKE ? ESCAPE '\\')")
            clauses.append(f"({group})")
            args += extra + [like, like]
        rows = [dict(r) for r in db().execute(
            "SELECT * FROM sales WHERE " + " AND ".join(clauses) + " ORDER BY id DESC",
            args).fetchall()]
    else:
        rows = [dict(r) for r in db().execute("SELECT * FROM sales ORDER BY id DESC")]
    pays = db().execute(
        """SELECT sale_id, method, amount, commission_amount, commission_mode, note
           FROM payments ORDER BY id""").fetchall()
    split = {}
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
    total = sum(r["total"] for r in rows)
    if (request.args.get("format") == "json" or
            request.headers.get("X-Requested-With") == "xhr"):
        return jsonify(q=q, total=round(total, 2), rows=[
            {"id": r["id"], "ref": r["ref"], "created_at": r["created_at"],
             "item_count": r["item_count"], "total": round(r["total"], 2),
             "split": r["split"], "customer_phone": r["customer_phone"],
             "customer_note": r["customer_note"]} for r in rows
        ])
    return render_template("sales.html", sales=rows, total=total, q=q)


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
    surcharge = round(sum(surcharge_of(methods.get(p["method"]), p["amount"]) for p in pays), 2)
    return render_template("receipt.html", sale=sale, items=items, pays=pays,
                           commission=commission, surcharge=surcharge,
                           vat=sale["vat_amount"] or 0, methods=methods)


@app.route("/sales/<int:sale_id>/void", methods=["POST"])
def sale_void(sale_id):
    conn = db()
    sale = conn.execute("SELECT * FROM sales WHERE id = ?", (sale_id,)).fetchone()
    if sale:
        for it in conn.execute("SELECT * FROM sale_items WHERE sale_id = ?",
                               (sale_id,)).fetchall():
            if it["product_id"] is not None:
                conn.execute("UPDATE products SET qty = qty + ? WHERE id = ?",
                             (it["qty"], it["product_id"]))
            elif it["set_id"] is not None:
                for c in set_components(conn, it["set_id"]):
                    conn.execute("UPDATE products SET qty = qty + ? WHERE id = ?",
                                 (it["qty"] * c["per_set"], c["id"]))
        conn.execute("DELETE FROM sale_items WHERE sale_id = ?", (sale_id,))
        conn.execute("DELETE FROM payments WHERE sale_id = ?", (sale_id,))
        conn.execute("DELETE FROM sales WHERE id = ?", (sale_id,))
        conn.commit()
        flash(f"Sale {sale['ref']} voided and stock returned.", "ok")
    return redirect(url_for("sales"))


# -------------------------------------------------- template globals
@app.context_processor
def erp_globals():
    rows = payment_rows()
    return {"PAY_METHODS": {r["key"]: r["label"] for r in rows},
            "PAYMENT_METHODS": [dict(r) for r in rows]}


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
