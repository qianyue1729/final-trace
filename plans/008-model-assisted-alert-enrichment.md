# Plan 008: Add model-assisted alert enrichment with abstention

> **Executor instructions**: Rules and inventory enrich first; the model fills
> semantic gaps and may abstain. Never convert an unknown alert to `T0000` or
> default `execution` and then present it as fact. Update the plan index.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_engine\service\app.py,`
>   src\trace_engine\runner.py,`
>   src\trace_engine\normalizer.py,`
>   src\trace_agent\loop\scenario_executor.py
> ```
>
> Expected:
> `58102494F2F0C5DF1BA5998A8C07FA1B7D1D76D7D47847C09B21B72E93D5AFC2`,
> `5FD076638163E8AC6407FA49B02F25FA6C96E09040F02AB9887CCB5F565679E7`,
> `6BB0C3684E2DF84954BD64CF0F226CC8D569434932C40CA840FCFD7816271638`,
> `5D5C4ECCA4A0E4317C44EA3DE12B12C1493D5E5E11C38A821FA955DCE9D1FD11`.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — enrichment affects seed hypotheses and downstream queries
- **Depends on**: Plans 001 and 003
- **Category**: direction / architecture
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

The API requires a MITRE technique and does not expose platform even though the
seed model supports it. Real alerts often contain only rule title, event ID,
process lineage, command line, cloud action, or vendor taxonomy. Static maps
pick the first list value, default unknowns to `T0000`/`execution`, and lose
uncertainty before investigation begins.

## Current state

- `AlertIn` requires `technique` and `asset` at
  `src/trace_engine/service/app.py:32-40`; it has no platform field.
- `build_alert()` falls back to `T0000` and `_technique_tactic()` falls back to
  `execution`.
- `EventNormalizer` takes the first technique/tactic from a list.
- `ScenarioExecutor` uses partial static technique/action/source maps.
- `AlertEvent` already supports platform, log source, anomaly score, and
  attributes, so the downstream schema can carry richer context.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| Normalizer/API | `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_normalizer.py tests\engine\test_api_e2e.py -q` | all pass |
| Enricher tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_alert_enricher.py -q` | all pass |
| Full suite | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |

## Scope

**In scope**

- `src/trace_engine/service/app.py`
- `src/trace_engine/runner.py`
- `src/trace_engine/normalizer.py`
- new `src/trace_engine/alert_enricher.py`
- `src/trace_engine/config.py`
- ATT&CK catalog validation through `PriorManager`
- API/normalizer/enricher tests and documentation

**Out of scope**

- Raw unrestricted log forwarding to an external model.
- Model-generated probabilities used as calibrated confidence.
- Silent selection of one technique from multiple plausible candidates.
- Model access to SOAR tools.

## Target input/output

Input supports optional technique plus:

- vendor/rule identifiers and title;
- platform/asset role from CMDB;
- event/log source identifiers;
- parent/child process and bounded command-line features;
- cloud/API action and network direction;
- redacted structured attributes.

Output:

```json
{
  "candidates": [{
    "technique": "T1059.001",
    "tactics": ["execution"],
    "supporting_fields": ["rule.title", "process.command_line"],
    "score": 0.0,
    "score_status": "uncalibrated"
  }],
  "platform": "windows",
  "log_source": "sysmon",
  "abstained": false,
  "reason_codes": []
}
```

## Steps

### Step 1: Expand and validate the API contract

Make technique optional only when sufficient raw structured alert context is
provided. Add platform, vendor/rule fields, and bounded enrichment attributes.
Apply size limits and reject unexpected large/raw blobs.

### Step 2: Implement deterministic enrichment first

Use field mapping, OCSF/vendor mappings, CMDB platform/role, and the full prior
ATT&CK catalog. Preserve multiple supplied techniques instead of taking the
first. Record provenance for every field.

### Step 3: Add a provider-neutral AlertEnricher

Call the model only when required fields remain ambiguous. Treat all strings as
untrusted. Require structured candidates, supporting input-field paths, reason
codes, and abstention. Validate techniques/tactics/platforms against catalogs.

### Step 4: Preserve ambiguity through seeding

Do not collapse candidates before DecisionLedger. Seed competing explanations
or an explicit unknown-technique explanation with high entropy. `T0000` must
not masquerade as a real technique.

### Step 5: Add privacy and provider controls

Redact secrets, tokens, emails/user IDs as policy requires; cap command-line
length; record provider/model/schema version and hashes of cited fields rather
than raw sensitive content. Support local/private provider mode.

### Step 6: Launch in shadow mode

When clients already provide technique/platform, run enrichment in shadow and
measure candidate recall, top-k accuracy, abstention, disagreement, latency,
and cost against independent labels. Enable assist only for validated slices.

### Step 7: Feed status, not false confidence, downstream

Expose enrichment provenance and score status in the report. Plan 003 decides
whether any calibrated mapping probability exists.

## Test plan

- Known ATT&CK input passes without model.
- Missing technique with sufficient context.
- Multiple candidates preserved.
- Unknown/unsupported technique and abstention.
- Invalid model technique rejected.
- Prompt injection and oversized raw fields.
- Platform/asset-role enrichment from inventory.
- Provider timeout falls back to explicit unknown.

## Done criteria

- [x] API can accept a well-formed raw alert without preassigned ATT&CK.
- [x] Unknown does not silently become `T0000/execution`.
- [x] Every enriched field has provenance.
- [x] Model can abstain and cannot invent catalog entries.
- [x] Shadow metrics and privacy controls exist.
- [x] Full suite passes.
- [x] Plan index updated.

Implementation result (2026-07-03): alert enricher `29 passed`; full
engine/core `352 passed`. Default mode is `off`; deterministic enrichment
runs even in off mode (ATT&CK catalog + vendor/process maps). Shadow mode
records model candidates without affecting the alert; assist mode adds
validated model candidates. Unknown technique uses `T0000` with
`unknown_technique=True` and `tactic="unknown"` — never masquerades as
`execution`. Privacy redaction strips passwords/tokens/emails before model
calls. Command-line truncation and attribute size limits enforced.

## STOP conditions

- Input data cannot be sent to the configured provider under policy.
- The ATT&CK catalog/prior bundle version is unavailable.
- A downstream component still requires exactly one technique.
- Independent labels are unavailable for assist-mode graduation.

## Maintenance notes

Vendor schemas, ATT&CK versions, model versions, and redaction policy are
independent version axes. A change to any one requires shadow revalidation.
