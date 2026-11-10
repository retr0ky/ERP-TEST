"""Push the local erp.db into the hosted Turso database (ids preserved, idempotent).

Run:  python3 sync_to_turso.py            (reads .env for TURSO_URL / TURSO_TOKEN)
Existing rows with the same id are left alone; only missing rows are added.
"""
import sqlite3

import app

TABLES = ["categories", "suppliers", "products", "sets", "set_products",
          "payment_methods", "sales", "sale_items", "payments", "held_carts"]


def shared_columns(local, remote, table):
    local_cols = [r["name"] for r in local.execute(f"PRAGMA table_info({table})").fetchall()]
    remote_cols = [r["name"] for r in remote.execute(f"PRAGMA table_info({table})").fetchall()]
    return [c for c in local_cols if c in remote_cols], remote_cols


def bump_sequence(remote, table, max_id):
    try:
        remote.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = ?", (max_id, table))
    except Exception as exc:
        print(f"  sequence bump skipped for {table}: {exc}")


def parents(local, table):
    """Rows the FKs of `table` point at - Turso enforces FKs, the old local file never did."""
    out = []
    for fk in local.execute(f"PRAGMA foreign_key_list({table})").fetchall():
        parent, col, pcol = fk["table"], fk["from"], fk["to"]
        if parent not in TABLES and parent != table:
            continue
        ids = {r[0] for r in local.execute(f"SELECT {pcol} FROM {parent}").fetchall()}
        out.append((col, ids))
    return out


def copy(local, remote):
    for table in TABLES:
        cols, _ = shared_columns(local, remote, table)
        if not cols:
            print(f"{table}: missing on Turso - skipped")
            continue
        rows = local.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()
        if not rows:
            continue
        fks = parents(local, table)
        kept = [r for r in rows
                if all(r[col] is None or r[col] in ids for col, ids in fks)]
        dropped = len(rows) - len(kept)
        if dropped:
            print(f"{table}: dropping {dropped} row(s) pointing at deleted parents")
        if not kept:
            continue
        sql = (f"INSERT OR IGNORE INTO {table} ({', '.join(cols)})"
               f" VALUES ({', '.join('?' for _ in cols)})")
        remote.executemany(sql, [tuple(r) for r in kept])
        print(f"{table}: {len(kept)} rows pushed")
        if "id" in cols:
            max_id = max(r["id"] for r in rows)
            if max_id:
                bump_sequence(remote, table, max_id)


def main():
    local = app.DB(sqlite3.connect(str(app.DB_PATH)))
    app.init_db(local)                 # migrate + casefold-fill the local file first
    remote = app.connect()
    if not app.TURSO_URL:
        raise SystemExit("TURSO_URL is not set - put it in .env or export it.")
    app.init_db(remote)
    copy(local, remote)
    remote.commit()
    for table in TABLES:
        try:
            n = remote.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  Turso {table}: {n}")
        except Exception as exc:
            print(f"  Turso {table}: {exc}")
    remote.close()
    local.close()


if __name__ == "__main__":
    main()
