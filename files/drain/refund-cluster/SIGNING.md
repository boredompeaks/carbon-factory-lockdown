# Signing status - refund cluster

Cryptography was dropped on 2026-11-06. There is one Windows host and no trust boundary
between the agent and the disk: a signature produced by the same process that writes
the record proves nothing. Every ledger record carries
`sig_status: "unsigned_local"` and a `record_hash` over canonical JSON with the
`record_hash` field removed. Chained records also carry `prev_hash`; the first
record uses 64 zeroes.

R1-R3 are sealed against live `policy_digest`
`2d34342d56cf813d82900e1defdab4b37cc86f5a36a547acf233dda75b4c3d35`
(the five gated policy files: `tiers.json`, `severity.json`,
`negative-controls.json`, `check-runners.json`, `layers.json`):

- R1 `270fa8ee021f1f280b49bcbd6db910759bc0e5f08213a1f0f7b03a65db39310a`
- R2 `e7c49f0a91d9d8e3ff5c5b46566c151351e75029917dd153e9f04e1fed9f6641`
- R3 `26444f79f268720f58d1037cc3d26c14013484603c75b98c820e785d3da04354`
- capability `eed1c118a56feb0cbcb4865d58c095ddeb0b04c98ce6cb9b84fcefd7f8b2cc22`
- dispatch `8548ad71f70846743efa08a355d67d3848d9ff8d3ab3b6478887b26ed8daa50f`

Gate-control records (the ledger is supersession-rewritten; the newest seal is the only PASS — seal->verify->declare, see "Seal order (enforced)" below; pre-rewrite bytes are preserved in immutable backups):

- `0001-7567ce1902de.json` - SUPERSEDED, `superseded_by: 0004-7567ce1902de.json`, `hash_recomputed: true`, record_hash `ede98c54e77b94a6d823883a19800e43e35400cf34ef41c39e9c6fad76a52c91`
- `0002-7567ce1902de.json` - SUPERSEDED, `superseded_by: 0004-7567ce1902de.json`, `hash_recomputed: true`, record_hash `f67d6081915dfa03116fc99b3c3f519f78b7d59ca7736fcbc9f14620574b9cdb`
- `0003-7567ce1902de.json` - SUPERSEDED, `superseded_by: 0004-7567ce1902de.json`, `hash_recomputed: true`, record_hash `2ad223bd5f368a5a35b6fe11cd9732cf8859ccd3c37864353947c23abcbd2cb1`
- `0004-7567ce1902de.json` - PASS (historical; now SUPERSEDED -> `0008-7567ce1902de.json`, see re-seals 0005-0008 below), record_hash `1b07e2c54effc94b4e2440fa57b07cfd0a2bf12ac4a7eeeec67b420a58cbc602`
- controls: `19` known-bad / `35` total entries, `19` rejected, `total_min` `13`
- `gate_sha` `7567ce1902de1fb57b908d2341ba8812337c5ee2`
- `gate_impl_digest` `ec1fc16aeab22f25855ce61bd222d93ac1c0624d29ff8aaf3b68e219e00f11c7`
- `control_set_sha` `afb621f86b86dd564ca3643b77537fbd20f2ba38459d1a54fa2a533829846e72`
- `policy_digest` `2d34342d56cf813d82900e1defdab4b37cc86f5a36a547acf233dda75b4c3d35`

## Ledger model — supersession-rewritten (not append-only)

Each re-seal appends the newest record, then rewrites `0001`..`N-1` to `state=SUPERSEDED`, `superseded_by=<newest>`, recomputing `prev_hash`/`record_hash` in order. This in-place recomputation is the normal path (not a backfill exception): pre-rewrite bytes are first preserved in an immutable backup directory (`files/quality/ledger/gate-control-backup-<timestamp>/`, e.g. `...-133424` for 0005, `...-200213` for 0006, `...-201326` for 0007); backups are never edited. `hash_recomputed=true` on 0001-0003 remains the historical marker of the first backfill rewrite.

R3 evidence log sha256 `244af79949236730b1596c517b8bbdd272bb4b0e433b344f69f1915287d4cf75`
(`C:/Users/Admin/AppData/Local/Temp/opencode/audit-logs/gate0-r12-r3-base.log`).

`dispatch.json` is `DISPATCH` / `OK`: P-CTRL, P-HEAD, P-SCOPE, P-TIER and P-BUDGET
were evaluated against the sealed records above. P-CTRL passes on record-hash
validity, chain continuity, the live policy digest (five-file scope), the live
gate-implementation digest, the resolved control-set hash, and
`controls_rejected == controls_total`. 3 stages: `superseded` records do not
participate in verification beyond hash/chain validity; only the newest gate-control
record may verify PASS. The dispatch gate-control ref is
`quality/ledger/gate-control/0004-7567ce1902de.json` at
`1b07e2c54effc94b4e2440fa57b07cfd0a2bf12ac4a7eeeec67b420a58cbc602`.
`tools/validatedrain.py` confirms the full lineage PASS.

## 2026-11-07 re-seal (0005)

- `policy_digest`: `2d34342d56cf813d82900e1defdab4b37cc86f5a36a547acf233dda75b4c3d35` -> `c847118644fa18d704773ba3f9a8892b13b756f9c67afb322607d6f927f631a8` (five gated files; `negative-controls.json` changed).
- Count fix: `controls_total=53`, `total_min=53`, `known_bad_min=28`; `ORACLE_PROVENANCE.min_count` corrected 5 -> 3 to match its 3 known-bad controls. Live gate-control dry run: PASS, 28/28 known-bad rejected, `all_rejected=true`, no errors; `control_set_sha=971f1fdac1698a8b43265de31b13dca97126848dedf56bb8aed7eff0cb481267`.
- Newest gate-control record: `0005-7567ce1902de.json`, `record_hash=2fd5460bff5e8248a2c5a86100c47258bbff0923aa1c1aad62c29696100c2a21`, `result=PASS`, `gate_sha=7567ce1902de1fb57b908d2341ba8812337c5ee2`, `gate_impl_digest=862407a53de1ca8ffd7a48943ceddb3a9c2a544c0136da3707810910200c2a0b`, `controls_total=28`, `controls_declared=53`, `known_bad_min=28`.
- Chain rewrite for superseded_by re-link: `0001`-`0004` set SUPERSEDED -> `0005-7567ce1902de.json`; `prev_hash`/`record_hash` recomputed in order 0001 -> 0005. Original bytes at `C:\Users\Admin\Documents\umairnlp\files\quality\ledger\gate-control-backup-20261107-133424`.
- New gate-control record hashes: `0001` `fb2d0cdcc9bf2398739bb20944f5fa1362434b7095a409bbaedfd1b80fcd9758`, `0002` `fa79da6d893baac78c705823ea847be3a95f04e1060dd13c6ced527d04e7ab91`, `0003` `fda70425d03828d8a77fb09abb5abcbbdea9ad7b534afaa9b0b41573bda9cd6c`, `0004` `7b6e82aa8dfbb3f3af522e73d4b3d5c8177716a63e854cdb54ce3625c37e36a7`, `0005` `2fd5460bff5e8248a2c5a86100c47258bbff0923aa1c1aad62c29696100c2a21`.
- Re-sealed drain lineage: R1 `33345ec26f55a62d9c458a3ef65e0166b380e2012167e68e90d76108af4d5690`, R2 `884a4636c1914a437bcf1b8c8fe670144094c9f15c6f29c58c37212d8e0c7e02`, R3 `96e91a5edba1cb61f0678ccdc99bb9d34228dfbf20d28487d3e9f06092fb8c85`, capability `1ab9b74dac4809ad2d6797e3d378efbcffbb59f3914205c16fb501b9e8d7615d`, dispatch `941d1ce1f9f982dd277563236bbd5fa69fbcdddfea18948659a490749cf6195f`, R4 addendum `1e7245535c58cfdf00dddc75b0a36bcc282ba626c3b1aa1e3282d22259db66dd`.
- Capability now pins base `9b10e00078e0ad9a151ae8d1c4b9fbbcf1450644`, head `12c96d1117c1a581eafe4a5c780a12f45808e30c`, tree `2b9a36e189da1ebb77afab63b6245353f38ee7bc`, the 15-file release scope, `task_branch`/`branch`/`base_branch` `spec-comp`, `drain_stage` `R4`.
- Dispatch state carries the same base/head/tree; evidence refs now name the re-sealed R1/R2/R3 hashes, the live `policies` digest, and `quality/ledger/gate-control/0005-7567ce1902de.json` at `2fd5460bff5e8248a2c5a86100c47258bbff0923aa1c1aad62c29696100c2a21`. The audit-log ref remains at sha256 `244af79949236730b1596c517b8bbdd272bb4b0e433b344f69f1915287d4cf75` (file present, hash unchanged).
- Verification actually run: `python files\tools\gate_control.py --verify files\quality\ledger\gate-control\0005-7567ce1902de.json` exit 0, result PASS, problems []; `python files\tools\gate_control.py --verify-chain` exit 0, chain_size 5, newest_result PASS, problems []; `python files\tools\validatedrain.py` exit 0, result PASS, records_checked 3, problems [].


## 2026-11-07 re-seal 0006 (gate_impl change: opencode.json provider/fallback + permission hardening)

- Reason: `opencode.json` moved (GLM on opencode-go, MiniMax on the Nous direct portal with an
  opencode-go fallback; permission hardening in the agent contracts does not move a digest).
- Newest gate-control record: `0006-7567ce1902de.json`, `record_hash=0e912f342871faf74fbf7b92afb233fed8556ab58c5f8c972d35d23fe2f73242`,
  `result=PASS`, `policy_digest=c847118644fa18d704773ba3f9a8892b13b756f9c67afb322607d6f927f631a8`,
  `control_set_sha=971f1fdac1698a8b43265de31b13dca97126848dedf56bb8aed7eff0cb481267`,
  `gate_impl_digest=0fe32eea917bd98b9e9cde2f58074c99754c59b34ef4209bce3ad5115b467bba`.
- Chain: `0001`-`0005` set SUPERSEDED -> `0006-7567ce1902de.json`; `prev_hash`/`record_hash`
  recomputed in order. Original bytes for the 0005 seal remain in the
  2026-11-07T13:34:24 backup directory.
- Dispatch gate-control evidence ref updated to `quality/ledger/gate-control/0006-7567ce1902de.json`
  at `0e912f342871faf7...`; dispatch `record_hash=a2e79b80d7f6e8ec280bbc61d165b2f6a186d1c901cc2513c99c5d28f7c1530c`.
- Declare PASS only after `seal -> verify -> declare`: run `gate_control.py --verify`,
  `--verify-chain`, and `validatedrain.py` and record their output verbatim in an addendum; never mutate the sealed record or a backup to make verify pass.

## 2026-11-07 re-seal 0007 (R05-10: no agent access to the OpenCode control tree)

- Reason: `.agt/policy.json` gained `directResourcePolicies.pathRules` denying
  `**/.opencode/**`, `**/.config/opencode/**`, `**/.local/share/opencode/**`.
  This is a policy/gate change, so it moves `gate_impl_digest`; permission-only
  contract edits still do not.
- 0007: `gate_impl_digest=34ffd85bd7dc6ad5d68c7ebdcb1ba94a621da524d39e5d3543b96bd7b9637308`,
  `record_hash=02f12fe7438885ca1ee8ad44b0057c14828ad1e3f5c96e954a7555666a06a4e9`,
  `policy_digest`/`control_set_sha`/`gate_sha` unchanged. Superseded by 0008.

## 2026-11-07 re-seal 0008 (R05-10: scrub grep/glob results)

- Reason: `grep`'s permission resource is the regex, not the path, so a
  root-wide grep still returned `.opencode` lines. `.opencode/plugins/agt.js`
  now scrubs control-tree lines from `grep`/`glob` results in `execute.after`.
- Newest gate-control: `0008-7567ce1902de.json`,
  `record_hash=3722fb8964d0fc4910d59e4084b1b29f4831f41489cc6e237239c686c2602afe`,
  `gate_impl_digest=224cbf99bf50d4caa79d6d27c1a2098507ca013ee555a2ce91ceed4cb97c096d`,
  `policy_digest=c847118644fa18d704773ba3f9a8892b13b756f9c67afb322607d6f927f631a8`,
  `control_set_sha=971f1fdac1698a8b43265de31b13dca97126848dedf56bb8aed7eff0cb481267`,
  `gate_sha=7567ce1902de1fb57b908d2341ba8812337c5ee2`.
- Chain 8: `0001`-`0007` SUPERSEDED -> `0008`; hashes recomputed in order.
  Current chain hashes: `0001 9a686d08`, `0002 1de183db`, `0003 581da16d`,
  `0004 06536454`, `0005 2973641f`, `0006 264f3e8d`, `0007 11e49fba`,
  `0008 3722fb89`.
- Dispatch gate-control evidence ref -> `quality/ledger/gate-control/0008-7567ce1902de.json`
  @ `3722fb8964d0fc4910d59e4084b1b29f4831f41489cc6e237239c686c2602afe`;
  dispatch `record_hash=332abb210b6d61c76763f67290c3a9500ce730e8dbae89c9763fc3e7abffae73`.
- Verified at seal time: `--verify 0008` PASS; `--verify-chain` PASS (8, newest 0008);
  `validatedrain.py` PASS (3). Live orchestrator probe: read and glob on
  `.opencode` denied; grep with an `.opencode` path denied; root grep/glob
  return 0 `.opencode` paths; ledger grep/read still allowed.

## Seal order (enforced)

1. **Seal** (`gate_control.py --write`) writes the newest record and supersession-rewrites the chain (backups first, see "Ledger model" above).
2. **Verify** `gate_control.py --verify <newest>`, `--verify-chain`, and `validatedrain.py`; all must print `result PASS` / `problems []`.
3. **Declare** PASS only after verify, recording the verify output verbatim in an addendum — **never mutate** a sealed record or a backup to make verify pass. A seal without a following verify is UNPROVEN, not PASS.

## Live verify status (read-only, docs fix only — no seal)

- `gate_control.py --verify 0008` = FAIL (exit 1, `policy_digest`/`gate_impl_digest`/`control_set_sha` differ from live); `--verify-chain` = FAIL (chain_size 8, newest 0008); `validatedrain.py` = FAIL (exit 1).
- Live digests `policy_digest f66f3264…`, `gate_impl_digest 3d27ef10…`, `control_set_sha 4a87aa83…` differ from `0008` (`c8471186…` / `224cbf99…` / `971f1fda…`).
- `0008` (`3722fb89…`) remains the newest seal; its seal-time PASS above is historical only. **No new PASS is claimed beyond `0008`** until a re-seal + verify passes and is recorded in an addendum.
## auto-seal 0023-c33efa8aae87.json 2026-11-09T18:42:59Z
- record: 0023-c33efa8aae87.json
- gate_sha: c33efa8aae87bd9cbc6ea42bc822765d74526e9e
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: df41dac826c4f480b2db7eb9ae295fdd315919453ca545067ed05bf73e6e9728
- record_hash: af5c43ad27a5db6d8920dff727862a508cf944167140cdc5e4117a629b6beb48
- result: PASS
## auto-seal 0024-404bd9e7c707.json 2026-11-09T18:44:05Z
- record: 0024-404bd9e7c707.json
- gate_sha: 404bd9e7c707734cff0a30bfb71db51c35dde742
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: df41dac826c4f480b2db7eb9ae295fdd315919453ca545067ed05bf73e6e9728
- record_hash: b364abc7a9bed79526d6176cbaba1692be10d32b778433fbd64afb57ec940c1e
- result: PASS
## auto-seal 0025-efc2055bb2ef.json 2026-11-10T03:31:26Z
- record: 0025-efc2055bb2ef.json
- gate_sha: efc2055bb2ef2527eafcb8fb5ded6f6f833e42b2
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 1bf4479575c2f3f6dccbc39809e90f1b679dc6dcde11f06a8e81d0f5df5d5ec3
- record_hash: 2f21898386e65842586d4bd76881dd6e9904123618b96a2f0b53a9a7b9cdc123
- result: PASS
## auto-seal 0026-a33935ea26bf.json 2026-11-10T03:31:56Z
- record: 0026-a33935ea26bf.json
- gate_sha: a33935ea26bfcc0ef5242e6c56c0c980c2be79c8
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 1bf4479575c2f3f6dccbc39809e90f1b679dc6dcde11f06a8e81d0f5df5d5ec3
- record_hash: cd3e9121cff015f61a8d16a0c0c0bb713457e2707446cd57be677b9e16135d84
- result: PASS
## auto-seal 0027-5955654a6326.json 2026-11-10T03:33:54Z
- record: 0027-5955654a6326.json
- gate_sha: 5955654a63261692e547855b4852861abf3c6170
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 1bf4479575c2f3f6dccbc39809e90f1b679dc6dcde11f06a8e81d0f5df5d5ec3
- record_hash: 05b04963a6a7cb9136fd15e117e13f8d420e0f6772db6476dfe8020387ea340b
- result: PASS
## auto-seal 0028-c3f85767266e.json 2026-11-10T03:34:27Z
- record: 0028-c3f85767266e.json
- gate_sha: c3f85767266e01944009b494a94725008adfe7df
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 1bf4479575c2f3f6dccbc39809e90f1b679dc6dcde11f06a8e81d0f5df5d5ec3
- record_hash: 4f360301af0dddce4a4fed5fa9813d98d34de6cba82c90aa070c7e98e2c35175
- result: PASS
## auto-seal 0029-7462c6cd85f3.json 2026-11-10T03:53:07Z
- record: 0029-7462c6cd85f3.json
- gate_sha: 7462c6cd85f3f661040869f720d5699a48746dd7
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 22b48fb4ffe7c86f53d0327f0002a7b35349f6e885241500dba4a64f5f60d63a
- record_hash: 9f4ae889c84c00fcaeeab8bd995c3bd6bca67d437e8a1a24c03033076f3a1b82
- result: PASS
## auto-seal 0030-9c808e9d9282.json 2026-11-10T03:53:39Z
- record: 0030-9c808e9d9282.json
- gate_sha: 9c808e9d9282b375a801814b44e799299340b401
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: 22b48fb4ffe7c86f53d0327f0002a7b35349f6e885241500dba4a64f5f60d63a
- record_hash: ab0536e20e40b14915860ab2a41447b0353b8fd583c2b04c17bf4252860d51aa
- result: PASS
## auto-seal 0031-3d8eb3cf2323.json 2026-11-10T04:20:47Z
- record: 0031-3d8eb3cf2323.json
- gate_sha: 3d8eb3cf23231aa0b54ad5e33829f76b35c7d182
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: eeb1e1e7f0d3f3ef92ef5387f2c8c3f64a73fd99b4543ffba0a2fa1dfc222621
- record_hash: e12fc34b89897f62806efc7962007ba8cd228794a008707204caa0726e5507a5
- result: PASS
## auto-seal 0032-e702c011ccfc.json 2026-11-10T04:21:20Z
- record: 0032-e702c011ccfc.json
- gate_sha: e702c011ccfcdce63265b3c16d6b59cd3c9e1e8e
- policy_digest: cfd6ef79571bbdb029d71cd08150521c01b1cec63d3318e509f9d83201d119c3
- control_set_sha: 4a87aa8351251a9cc90ece53afd3f1d543cc9b989a138efc58ac224500166011
- gate_impl_digest: eeb1e1e7f0d3f3ef92ef5387f2c8c3f64a73fd99b4543ffba0a2fa1dfc222621
- record_hash: 5ede26ed65bcbfc1db8ae9d9881acfc7a4c968049c30a170778994d3042cc1a6
- result: PASS
