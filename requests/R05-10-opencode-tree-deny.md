# R05-10 — No agent access to the OpenCode control tree

**Status:** APPLIED + SEALED (`0008-7567ce1902de.json`)
**Scope:** `.opencode` (local), `~/.config/opencode`, `~/.local/share/opencode`.
**Owner:** harness operator

## 1. Incident

After the external-directory batch (R05-09), a live orchestrator probe showed:

```
read C:\Users\Admin\Documents\umairnlp\.opencode\agents\orchestrator.md   -> ALLOWED (398 lines, full permission block)
grep "permissions" in C:\Users\Admin\Documents\umairnlp\.opencode          -> ALLOWED (100+ matches, incl. agents/*.md)
```

The permission layer had `read **` and (for compliance) `grep *`/`glob *`,
and no `.opencode` deny. A role could read its own and every other role's
contract, the plugin, and the skill tree.

## 2. Why the obvious fix is insufficient

OpenCode V2 permission resources are not uniform:

| Action | Resource |
|---|---|
| `read` | path |
| `glob` | requested glob pattern |
| `grep` | **requested regular expression**, not the search path |
| `external_directory` | canonical external boundary |

So a `grep` path deny can never match. The live probe confirmed it: the
`read` and `glob` denies worked, but `grep` still scanned `.opencode`.

## 3. Change

### 3.1 Contract denies (no seal)

All 7 contracts (`files/<role>.md` + `.opencode/agents/<role>.md`) gained,
after every allow:

```yaml
- { action: read,  resource: "**/.opencode", effect: deny }
- { action: read,  resource: "**/.opencode/**", effect: deny }
- { action: grep,  resource: "**/.opencode/**", effect: deny }
- { action: glob,  resource: "**/.opencode/**", effect: deny }
- { action: edit,  resource: "**/.opencode/**", effect: deny }
- { action: write, resource: "**/.opencode/**", effect: deny }
- { action: read,  resource: "C:/Users/Admin/.config/opencode/**", effect: deny }
- { action: read,  resource: "C:/Users/Admin/.local/share/opencode/**", effect: deny }
- { action: read,  resource: "C:/Users/Admin/.opencode/**", effect: deny }
# plus the root-relative forms the runtime actually matches:
- { action: read,  resource: ".opencode", effect: deny }
- { action: read,  resource: ".opencode/**", effect: deny }
- { action: grep,  resource: ".opencode", effect: deny }
- { action: grep,  resource: ".opencode/**", effect: deny }
- { action: glob,  resource: ".opencode", effect: deny }
- { action: glob,  resource: ".opencode/**", effect: deny }
```

The orchestrator keeps `grep **` / `glob **` for task decomposition; the
`.opencode`, hacker-skill, hacker-scratch, and secret `grep`/`glob` denies are
re-asserted after that allow.

### 3.2 AGT path rule (seal)

`.agt/policy.json` gained:

```json
"directResourcePolicies": {
  "pathRules": [{
    "id": "no-opencode-tree",
    "effect": "deny",
    "operation": "any",
    "pathPatterns": [
      { "source": "(^|/)\\.opencode(/|$)", "flags": "i" },
      { "source": "(^|/)\\.config/opencode(/|$)", "flags": "i" },
      { "source": "(^|/)\\.local/share/opencode(/|$)", "flags": "i" }
    ],
    "reason": "R05-10: the OpenCode control tree is not accessible to agents."
  }]
}
```

This blocks `read`/`glob`/`grep`/`edit`/`write`/`patch` when a path-like
argument names the control tree, even if the permission layer allows the
action. It moves `gate_impl_digest` -> seal `0007` (superseded by `0008`).

### 3.3 Result scrub (seal)

`grep` with no path still returns matches from a root-wide scan. `.opencode/plugins/agt.js`
now scrubs control-tree lines from `grep`/`glob` results in `execute.after`
before the model sees them. This moves `gate_impl_digest` -> seal `0008`.

## 4. Evidence (live orchestrator, `--standalone`)

```
read  .opencode\agents\orchestrator.md        EXIT 1  "agt-direct-resources: R05-10 ... Matched path ...\.opencode\..."
glob  .opencode/**                            EXIT 1  "Permission denied: glob"
grep  "permissions" path .opencode            EXIT 1  "agt-direct-resources: R05-10 ..."
read  C:\Users\Admin\.config\opencode\...     EXIT 1  "agt-direct-resources: R05-10 ..."
grep  "permissions" no path                   EXIT 0  0 returned paths under .opencode (scrubbed)
glob  **/*.md no path                         EXIT 0  0 returned paths under .opencode (scrubbed)
grep  "PRISTINE-13d1" path comp-wt\...\run    EXIT 0  1 match (PRISTINE-tasks.md:65)
read  comp-wt\...\PRISTINE-tasks.md           EXIT 0  allowed
```

## 5. Seal

- `0007` (path rule): `gate_impl_digest 34ffd85b…`, superseded.
- `0008` (result scrub, newest):
  `record_hash 3722fb89…`, `gate_impl_digest 224cbf99…`,
  `policy_digest c8471186…`, `control_set_sha 971f1fda…`.
- Chain 8, `--verify 0008` PASS, `--verify-chain` PASS, `validatedrain` PASS.
- Dispatch gate-control ref repointed to `0008` @ `3722fb89…`.

## 6. Residual

`grep` can still run from the root; the scrub removes `.opencode` lines from
the result, so the model never receives control-tree content. If a future
OpenCode version starts passing the search path to the grep permission, the
path rule will apply directly and the scrub becomes belt-and-suspenders.
