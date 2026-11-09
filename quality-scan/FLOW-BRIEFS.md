# Quality scan — flow briefs

Generated from the AST import graph of `comp-wt` @ `1ffe926`. Full plan: `C:\Users\Admin\AppData\Local\Temp\opencode\q-scan\PLAN.md`; machine plan: `agents.json`.

## Pilot briefs

### Q01 — orders payment / refund / admin (3,123 LOC) — DENSE
- `backend/orders/views/payment.py` (571)
- `backend/orders/views/refund.py` (259)
- `backend/orders/views/order.py` (77)
- `backend/orders/views/admin.py` (292)
- `backend/orders/views/__init__.py` (202)
- `backend/orders/management/commands/seed_e2e.py` (838)
- `backend/orders/management/commands/seed_demo.py` (163)
- `backend/orders/management/commands/remint_legacy_order_numbers.py` (163)
- tests: `backend/orders/tests_remint_order_numbers.py` (189)
- contract references (read-only, out of scope): `orders/models.py`, `orders/state.py`, `orders/inventory.py`, `orders/webhooks.py`, `common/errors.py`, `common/permissions.py`

### Q02 — cart flow (1,604 LOC) — THIN
- `backend/cart/models.py` (82), `services.py` (120), `serializers.py` (33), `urls.py` (7), `admin.py` (31), `apps.py` (3), `__init__.py`, `management/__init__.py`
- tests: `backend/cart/tests.py` (600), `tests_merge.py` (208), `test_csrf.py` (230)
- contract references: `orders/views/checkout.py` (cart→order merge seam), `common/errors.py`
