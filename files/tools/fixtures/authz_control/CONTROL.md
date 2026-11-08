# authz_control fixture

A minimal Django/DRF control project for `authz_matrix.py`.  It has no
`backend/manage.py`, so the tool bootstraps it with an in-memory Django
settings object and `ROOT_URLCONF = authz_control.urls`.

## Routes

| Method | Route | View | Permission classes / gate | Derivation | Expected (admin/viewer) | Source |
|---|---|---|---|---|---|---|
| GET | `/public/` | `authz_control.views.PublicView` | `AllowAny` | PUBLIC | allow / allow | resolver |
| GET | `/gated/` | `authz_control.views.GatedView` | `HasWidgetWriteOrReadOnly` (reads) | PUBLIC | allow / allow | resolver |
| POST | `/gated/` | `authz_control.views.GatedView` | `HasWidgetWriteOrReadOnly` (`write_capability`) | CAPABILITY | allow / deny | resolver |
| GET | `/cap/` | `authz_control.views.CapView` | `HasWidgetWrite` | CAPABILITY | allow / deny | resolver |
| GET | `/decorated/` | `authz_control.views.decorated` | `@staff_only` (`staff_only`, `login_required`, `user.is_staff`) | STAFF | allow / allow | function |
| GET | `/widgets/` | `authz_control.views.WidgetViewSet.list` | `AllowAny` | PUBLIC | allow / allow | router |
| POST | `/widgets/(?P<pk>[^/.]+)/poke/` | `authz_control.views.WidgetViewSet.poke` | `AllowAny` | PUBLIC | allow / allow | viewset_action |

`HasWidgetWrite` maps to the capability `widget.write`; the fixture
`roles.json` grants it to `admin` only.  `/decorated/` has no DRF permission
class; its gate exists only in the decorator chain, which is why the control
run asserts `--require-derivation /decorated/=STAFF`.

## Control run

Command:

```
C:\Users\Admin\AppData\Local\Temp\opencode\comp-wt\backend\venv\Scripts\python.exe authz_matrix.py --repo fixtures\authz_control --roles-file fixtures\authz_control\roles.json --require-derivation /decorated/=STAFF --out fixtures\authz_control\control-matrix.json --summary
```

Result: **exit 0**, **6 routes**, **7 rows**, **0 missing rows**.

Derivation histogram: `PUBLIC=3 AUTHENTICATED=2 STAFF=1 CAPABILITY=1 OWNER=0 UNKNOWN=0`.

Source histogram: `resolver=4 router=1 viewset_action=1 function=1`.

## Negative controls

Required-route absence:

```
C:\Users\Admin\AppData\Local\Temp\opencode\comp-wt\backend\venv\Scripts\python.exe authz_matrix.py --repo fixtures\authz_control --roles-file fixtures\authz_control\roles.json --require-route /missing/ --out fixtures\authz_control\control-missing.json --summary
```

Result: **exit 1**, **7 rows**, and
`required_routes_missing: ["/missing/"]`.

Required-derivation mismatch:

```
C:\Users\Admin\AppData\Local\Temp\opencode\comp-wt\backend\venv\Scripts\python.exe authz_matrix.py --repo fixtures\authz_control --roles-file fixtures\authz_control\roles.json --require-derivation /gated/=PUBLIC --summary
```

Result: **exit 1**, and
`required_derivations_missing: ["/gated/=PUBLIC"]`.  `/gated/` mixes a
PUBLIC GET row with a CAPABILITY-gated POST row, so requiring PUBLIC across
every method row must fail.  This is the control that fails when per-row
derivation consistency regresses to a first-row-only check.
