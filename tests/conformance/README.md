# DELTA Conformance Tests

**Version:** v2.6.2 draft  
**Status:** Planning and documentation layer

This directory is reserved for DELTA conformance tests.

As of v2.6.2, the repository defines draft conformance levels and a conformance test plan. The full automated conformance runner will be added in a later milestone.

## Current conformance assets

- `docs/standard/conformance-levels-v2.6.2.md`
- `docs/standard/conformance-test-plan-v2.6.2.md`
- `tests/vectors/canonical-json/vectors.json`
- `schemas/schema-registry.json`
- `docs/test-vectors/`

## Initial manual checks

### L0: Canonical JSON

```powershell
python tools\delta_canonical_json.py verify-vectors `
  --vectors tests\vectors\canonical-json\vectors.json
```

Expected:

```text
DELTA_JCS_VERIFY_OK=True
```

### L1: Public reference verification

```powershell
python src\delta_cli.py verify-all
```

Expected:

```text
DELTA CLI RESULT: OK
```

### Schema JSON parse check

```powershell
@'
import json
from pathlib import Path

ok = True
for p in sorted(Path("schemas").glob("*.json")):
    try:
        json.loads(p.read_text(encoding="utf-8"))
        print(f"SCHEMA_JSON_PARSE_OK={p}")
    except Exception as exc:
        ok = False
        print(f"SCHEMA_JSON_PARSE_OK=False path={p} reason={type(exc).__name__}:{exc}")

if not ok:
    raise SystemExit(1)

print("DELTA_SCHEMA_JSON_PARSE_OK=True")
'@ | python -
```

Expected:

```text
DELTA_SCHEMA_JSON_PARSE_OK=True
```

## Future conformance runner

A future automated runner should support:

```text
delta conformance run --level L0
delta conformance run --level L1
delta conformance run --level L2
delta conformance run --level L3
delta conformance run --level L4
delta conformance run --level L5
```

This does not exist in v2.6.2. It is intentionally documented as future work.

## Security boundary

Conformance tests verify protocol behavior for a claimed level. They do not prove legal truth, real-world truth, identity, wallet balance, regulatory compliance, or evidence origin truth.
