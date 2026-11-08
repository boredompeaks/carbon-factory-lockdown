# Policy lint for 6A-4 (fail-closed); exit 0 only if every check passes.
import json, os, re, sys
import jsonschema

POL = 'C:/Users/Admin/Documents/umairnlp/files/policies'
FX = 'C:/Users/Admin/Documents/umairnlp/phase6/out/6A-4/fixtures'
fails = []
notes = []

def check(name, ok, detail=''):
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")
    if not ok:
        fails.append(name)

# 1. every policy json parses
ok, bad = True, []
for dp, _dn, fn in os.walk(POL):
    if 'schemas' in dp.split(os.sep):
        # schemas are validated separately (probe-record); still must parse
        pass
    for f in fn:
        if f.endswith('.json'):
            try:
                json.load(open(os.path.join(dp, f), encoding='utf-8'))
            except Exception as e:
                ok = False
                bad.append(f"{os.path.relpath(os.path.join(dp, f), POL)}: {e}")
check('all policy JSON parses', ok, str(bad))

cj = json.load(open(os.path.join(POL, 'checks.json')))
ci = json.load(open(os.path.join(POL, 'ci.json')))
bp = json.load(open(os.path.join(POL, 'branch-protection.json')))
src = json.load(open(os.path.join(POL, 'ci-required.json')))
sev = json.load(open(os.path.join(POL, 'severity.json')))

REQ = sorted(k for k, v in cj['checks'].items() if v['required_in_ci'])
check('ci-required.json == checks.json required_in_ci', sorted(src['required_checks']) == REQ, f'{len(REQ)} checks')
check('ci.json required_checks == single source', sorted(ci['required_checks']) == REQ)
check('branch-protection.json required_checks == single source', sorted(bp['required_checks']) == REQ)
check('ci.json has one-source pointer', ci.get('one_source') == 'files/policies/ci-required.json')
check('fixture drifted set fails the lint equality', sorted(json.load(open(os.path.join(FX, 'f71-drifted-set.json')))['required_checks']) != REQ)

# release-engineer proximity (cannot edit agent files in 6A-4): report as deferred
lines = open('C:/Users/Admin/Documents/umairnlp/files/release-engineer.md', encoding='utf-8').read().splitlines()
listed = []
for l in lines:
    if l.strip().startswith('SUITE, SECRETS, BOOTTEST'):
        listed = sorted([x.strip() for x in l.split('.')[0].split('Every')[0].split(',')])
notes.append(f'release-engineer.md prose list (lines 122-125) = {listed}; drift = {sorted(set(REQ) ^ set(listed)) or "none"}; deferred to 6C-1c (agent file not owned by 6A-4)')

# severity coverage
emits = {t for c in cj['checks'].values() for t in c['class_tags']}
sev_keys = {k for k in sev.keys() if not k.startswith('severity') and k not in ('version', 'default', 'blocking_severities', 'residual_severities', 'unknown_class', 'severity_scale')}
missing = emits - sev_keys
check('every checks.json class_tag in severity.json', not missing, f'missing={sorted(missing)}')
for cls in ['BARE_EXCEPT', 'AGT_PARITY_MISMATCH', 'AGT_AUDIT_GAP']:
    check(f'severity defines {cls}', cls in sev)
check('severity fail-closed unknown_class intact', sev.get('unknown_class', {}).get('action') == 'reject')

# registry class tags
reg = json.load(open('C:/Users/Admin/Documents/umairnlp/files/tools/mcp/registry.json'))
rtags = {t for tool in reg['tools'] for t in tool['class_tags']}
check('every registry class_tag in severity.json', rtags <= sev_keys, f'missing={sorted(rtags - sev_keys)}')

# test-removal exact match
trr = json.load(open(os.path.join(POL, 'test-removal-reasons.json')))['enforcement']['proof_rule']
check('covered_by is exact-match', 'EXACTLY equals' in trr and 'SUBSTRING' not in trr)
bad = json.load(open(os.path.join(FX, 'f73-covered-by-exact.json')))
check('f73 covered_by exact rule (substring rejected)', bad['covered_by'] != bad['added_ids'][0] and bad['covered_by'] in bad['added_ids'][0])

# assert-rules: compile + fixture cases
ar = json.load(open(os.path.join(POL, 'assert-rules.json')))
def compile_all(patterns):
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p['regex']))
        except re.error as e:
            out.append(None)
            check(f'assert pattern {p.get("id", p["regex"][:30])}', False, str(e))
    return out
taut = compile_all(ar['tautology_patterns'])
sc = compile_all(ar['oracle_provenance']['SELF_COMPARE']['patterns'])
check('assert-rules all patterns compile', all(x is not None for x in taut + sc),
      f'{len(taut)} tautology + {len(sc)} self-compare')
cases = [
    ('assert True, "looks fine" # done', True),
    ('assert count == count  # same var', True),
    ('self.assertEqual(a, a, "same")', True),
    ('self.assertTrue(True)', True),
    ('expect(true).toBe(true);', True),
    ('expect(x).toBe(x); // same', True),
    ('assert total == expected', False),
]
oks = []
for line, want in cases:
    hit = any(p.match(line) for p in taut + sc if p)
    oks.append(hit == want)
check('assert-rules fixture cases', all(oks), ','.join(str(o) for o in oks))

# redaction patterns
red = json.load(open(os.path.join(POL, 'redaction.json')))
def get_pii(name):
    return [p for p in red['pii_patterns'] if p['name'] == name][0]
phone = re.compile(get_pii('phone_nanp')['regex'])
ipv4 = re.compile(get_pii('ipv4_address')['regex'])
check('phone_nanp: bare digits no longer match', not phone.search('call 2125550199'))
check('phone_nanp: formatted still matches', bool(phone.search('call (212) 555-0199')))
check('ipv4: invalid octets no longer match', not ipv4.search('cache node 999.999.999.999 ttl'))
check('ipv4: valid dotted address matches', bool(ipv4.search('node 10.0.0.1 ttl')))
check('fixture_allowlist present', 'fixture_allowlist' in red and '127.0.0.1:8081' in red['fixture_allowlist']['exact_strings'])
def allowed(token):
    return token in red['fixture_allowlist']['exact_strings'] or any(re.match(p, token) for p in red['fixture_allowlist']['anchored_patterns'])
check('fixture allowlist pay_/ref_ ids', allowed('pay_3f9a1c2b4d5e6f70') and allowed('ref_ab12cd34ef56ab78'))

# probe-record schema
pr = json.load(open(os.path.join(POL, 'schemas', 'probe-record.json')))
good = json.load(open(os.path.join(FX, 'f-probe-record-valid.json')))['record']
badrec = json.load(open(os.path.join(FX, 'f-probe-record-invalid.json')))['record']
try:
    jsonschema.validate(good, pr); okv = True
except Exception as e:
    okv = False
check('probe-record validates a catalog-conformant record', okv)
try:
    jsonschema.validate(badrec, pr); okb = False
except Exception:
    okb = True
check('probe-record rejects an invalid record', okb)
cat = json.load(open(os.path.join(POL, 'attack-catalog.json')))
classes = {c for it in cat['items'].values() for c in it['probe_classes']}
check('probe_class enum == catalog probe_classes', set(pr['properties']['probe_class']['enum']) == classes,
      f'{len(classes)} classes')

print()
for n in notes:
    print('NOTE  ' + n)
print()
if fails:
    print('LINT FAILED:', fails)
    sys.exit(1)
print('POLICY LINT: ALL PASS')
