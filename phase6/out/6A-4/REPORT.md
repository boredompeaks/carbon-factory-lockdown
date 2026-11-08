# 6A-4 REPORT

- `files/policies/ci.json` sha256=4eed57d47fe2a2d1a74b49acaa54a1404ba167acfe76cfd86cc02cd43d907ed0 
- `files/policies/branch-protection.json` sha256=753ed18ec05b59cd20e4af2d9a6a24863b24a5578c6bd1d5a402fa9d13cce00c 
- `files/policies/ci-required.json` sha256=dc518d84c20e1bf26e09437ac35b54200a8ceba144936988f705b5a8667e7d18 
- `files/policies/severity.json` sha256=4693a00549eec31498d02cc7341ae7b37f5c539f2d304da75f460067757bf08e 
- `files/policies/test-removal-reasons.json` sha256=1697122375edd5f858b903b72c187a55c726c4321179a01977a7a1c1e0cfcee3 
- `files/policies/assert-rules.json` sha256=17fba355c1fe60ad212c5d2c7e3c7d21364830bb11dac20c852a18997a4b078d 
- `files/policies/redaction.json` sha256=a4c31530c11e558c0a7a64847f82551bd86d25b8876f1e092f377248f397b6db 
- `files/policies/schemas/probe-record.json` sha256=f37dc105f6f1743579199b1af1f7738dd9edff7757698791b06190a614f0dd21 
- `phase6/out/6A-4/digest.txt` sha256=ea66ff9896e138e487dd7af1f49e980544dccd43a0d4bd04b9c86760741bebab 
- `phase6/out/6A-4/lint.py` sha256=a7994afa903d0fe4d9cd4d34c89577e6f5ecb90e5febdbb8a1ee6ab49606b155 

## 6A-4 decisions (Block A rule 5 style, no scope creep)
1. release-engineer.md prose list (AUTHZ_MATRIX, ARCH missing) is NOT edited in 6A-4:
   agent files are outside files/policies/**. ci-required.json + lint assert the
   machine sources; 6C-1c regenerates the prose list from ci-required.json.
2. Redaction runner patch is 6B-0 server code; 6A-4 ships the policy allowlist
   (redaction.json.fixture_allowlist) including K1 fixture constants.
3. Fixtures live in phase6/out/6A-4/fixtures/ (NOT under files/policies/**) so the
   recomputed policy_digest covers only real policy changes. Digest (un-sealed)
   written to phase6/out/6A-4/digest.txt.
4. No git tag/branch: the repo is not a git checkout (no .git); rollback/tag ops
   belong to the OWNER session.
