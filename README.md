# ERP - POS + Inventory

Flask + SQLite (or hosted Turso/libsql) point of sale for one shop. No build step:
Jinja templates, one stylesheet, a little inline JS.

## Run locally

```bash
cd ~/Desktop/ERP-v2
pip install -r requirements.txt
python3 app.py                # http://127.0.0.1:5000
```

The first boot creates one **admin** account. Its password comes from
`ERP_ADMIN_PASSWORD`, else the legacy `ERP_PASSWORD`, else a generated one that is
printed once in the log. Log in, then add cashiers under **Accounts**.

## Accounts and roles

| | admin | cashier |
| --- | --- | --- |
| sell, hold carts, take payments | yes | yes |
| add new products, stock **in** | yes | yes |
| edit / delete / restore / purge products | yes | manager PIN |
| stock **out** (damage, loss, counts) | yes | manager PIN |
| sets, category rename/delete, void sales | yes | manager PIN |
| Accounts, Logs | yes | manager PIN |

The **manager PIN** (`ERP_MANAGER_PIN`) unlocks the admin tier for a cashier's session
for `ERP_ADMIN_WINDOW` seconds (15 min). The audit log records those actions as
`name+PIN`. Wrong PINs are throttled per account. While `ERP_MANAGER_PIN` is unset,
`ERP_ADMIN_PASSWORD` still works as the PIN (with a warning in the log). Set a separate
PIN so the cashier's PIN is not also the admin's password.

## Pages

- `/`, `/pos`: point of sale. Search or scan, tap products and sets into the cart, split
  payment across methods (Leasing needs a note), optional VAT, Complete sale.
- `/inventory`: products (live filter, sort, low-stock), sets, categories, deleted products,
  stock in/out with a reason.
- `/sales`: sales, newest first, 100 per page, searchable by ref, phone, note, item name or
  payment note. `/sales/<id>` is the printable receipt.
- `/logs` (admin): every stock move, with who did it, how much, why, and when.
- `/accounts` (admin): create users, change role, reset passwords, enable/disable.

## How the money and stock rules work

- **Checkout** is one transaction. A stock guard aborts the whole sale if any line can't be
  covered, so two tills can never sell the last unit twice.
- **Voids** keep the sale, marked `VOIDED` with who and when, and leave it out of the takings
  total. The stock returned is exactly what the sale took out, read from the audit log, so
  editing a set afterwards doesn't change what comes back. Sale numbers are never reused.
- **Surcharge** payment methods (`commission_mode = 'SURCHARGE'`) add their fee on top of
  that payment line: the total and the amount paid both include it. **Absorbed** fees are
  recorded but the shop pays them.
- **Every stock change is logged**: sales, voids, stock in/out, opening stock of a new
  product, and quantities typed on the edit form.
- Amounts are stored as REAL, rounded to 2 decimals on input, and printed without pointless
  decimals: `1,900,000₮`. The currency symbol is `CURRENCY` at the top of `app.py`.
- Timestamps are shop-local (`ERP_TZ`, default `Asia/Ulaanbaatar`), not the server's clock.
  Vercel and Turso run on UTC. Rows written before this change keep whatever zone they had.
- Purging a product keeps its past sale lines (`product_id` becomes NULL, the name stays).
  Purge is refused while the product is a component of a set.

## Environment variables

See `.env.example`. `.env` is read locally and never committed. On Vercel, set these under
Project Settings → Environment Variables.

| var | what it does |
| --- | --- |
| `TURSO_URL` / `TURSO_TOKEN` | use the hosted libsql database instead of `erp.db` |
| `ERP_SECRET_KEY` | signs session cookies. **Required** on Vercel, or every cold start logs everyone out |
| `ERP_PUBLIC=1` | secure cookies, debug forced off. Refuses to boot without `ERP_SECRET_KEY` |
| `ERP_ADMIN_USER` / `ERP_ADMIN_PASSWORD` | the first-run admin account |
| `ERP_MANAGER_PIN` | the manager PIN (falls back to `ERP_ADMIN_PASSWORD`) |
| `ERP_ADMIN_WINDOW` | seconds a PIN unlock lasts (default 900) |
| `ERP_TZ` | shop time zone for timestamps (default `Asia/Ulaanbaatar`) |
| `ERP_LOGIN_MAX_FAILS`, `ERP_LOGIN_WINDOW`, `ERP_LOGIN_LOCK_SECONDS` | login/PIN throttling (5 tries / 300 s, then 30 s doubling, max 1 h) |
| `ERP_TRUST_PROXY=1` | behind your own reverse proxy: take the client IP from the last `X-Forwarded-For` hop. Not needed on Vercel |
| `ERP_DEBUG=1` | Flask debugger for local development only. Never on a reachable host |
| `ERP_DB` | path of the local SQLite file (ignored when `TURSO_URL` is set) |
| `ERP_HOST`, `ERP_PORT` | `python3 app.py` bind address |
| `ERP_SALES_PAGE` | sales per page (default 100) |

## Hosting (Vercel + Turso)

`vercel.json` routes everything to `api/index.py` (`from app import app`). Push to GitHub and
Vercel redeploys. The schema migrates itself on the first request after a deploy (the
`schema_version` row in `meta`).

```
python3 sync_to_turso.py      # copy the local erp.db into Turso (keeps ids, only adds missing rows)
```

Local production-style run: `gunicorn wsgi:app`.

## Tests

```
python3 -m pytest             # runs every suite
python3 tests/test_fixes.py   # or one suite at a time
```

Each suite works on its own throwaway database file (`tests/*.db`, gitignored). None of them
touches the real `erp.db` or Turso.

## Files

```
app.py              routes, schema + migrations, DB adapter (SQLite / libsql)
templates/          Jinja templates (_cart_panel / _inv_rows are AJAX partials)
static/style.css    the one stylesheet, themes and print styles included
api/index.py        Vercel entrypoint;  wsgi.py: gunicorn entrypoint
sync_to_turso.py    local -> Turso copy
tests/              script suites + conftest.py (pytest runner)
CHANGELOG.txt       history
```
