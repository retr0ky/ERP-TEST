# ERP - Inventory + POS (single user)

Plain Flask + SQLite app. No login, no build step.

## Run

```bash
cd ~/Desktop/ERP
python3 app.py
```

Then open http://127.0.0.1:5000

Flask 3.1.3 was used here (already installed). If you need it: `pip install -r requirements.txt`.

## Pages

- `/` and `/pos` Point of sale (main screen): product search, tap products into the cart, split payment across Cash / Credit card / Bank transfer / Mobile wallet, then Complete sale (stock decrements)
- `/inventory` Search, add, edit, delete, adjust stock (in/out)
- `/sales` All sales with their payment split; `/sales/<id>` printable receipt, or void to return items to stock
- Amounts print without pointless decimals: `1,900,000₮` (not `1,900,000.00₮`)

## Files

```
app.py            routes + schema + first-run sample products
erp.db            SQLite database (created on first run; delete to start empty)
templates/        6 Jinja templates
static/style.css  single stylesheet, includes print styles
```

## Notes

- `CURRENCY = "₮"` at the top of `app.py` - change the symbol there.
- First run seeds 5 sample products. To start blank: delete `erp.db`, comment out `SEED`, or delete the products in the UI.
- Prices are stored as REAL; a cart is kept in the Flask session, so an abandoned cart lives only in that browser.
- Deleting a product keeps its past sale lines (`product_id` becomes NULL), so history survives.
- `ERP_SECRET_KEY` is read from the environment; without it a random one is generated per boot.

## Hosting (Vercel + Turso)

Vercel's disk is read-only, so `erp.db` cannot persist there. Set `TURSO_URL` +
`TURSO_TOKEN` and the same code writes to a hosted libsql (Turso) database instead.

```
python3 sync_to_turso.py      # push your local erp.db into Turso (keeps ids, safe to re-run)
```

Environment variables (see `.env.example`; `.env` is read locally and never committed):

| var | what it does |
| --- | --- |
| `TURSO_URL` / `TURSO_TOKEN` | use the hosted DB instead of `erp.db` |
| `ERP_PUBLIC=1` | forces a login gate, secure cookies, and requires the two vars below |
| `ERP_SECRET_KEY` | stable sessions across cold starts |
| `ERP_PASSWORD` | the single-user password/PIN |
| `ERP_HOST`, `ERP_PORT`, `ERP_DEBUG` | local `python3 app.py` overrides |

Vercel: import the repo, add those env vars, deploy; `vercel.json` routes everything to
`api/index.py` (`from app import app`). Local production-style run: `gunicorn wsgi:app`.

Tests: `python3 tests/test_search.py` and `python3 tests/test_leasing.py` - they run
against whichever backend the environment selects, so run them once with `TURSO_URL`
set to prove the hosted database behaves.
