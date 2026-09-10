# Delivery gate evidence

`scripts.delivery.gate_evidence` is the provider-neutral decision contract for
the delivery executor. A provider-specific adapter executes its own
filesystem, Compose, security, rollout, health, migration, smoke, or rollback
checks and passes only sanitized `GateEvidence` values to the evaluator.

The default required profile is:

```text
filesystem, compose, security, rollout, health
```

Every required gate must be present and report `passed`. Missing or `skipped`
required gates, any failed gate, duplicate gate names, unsupported names, and
invalid metadata fail closed. Optional `migration`, `smoke`, or `rollback`
evidence may be added; an optional skipped gate does not block the default
profile, but a reported failure still blocks the evaluation.

```python
from scripts.delivery.gate_evidence import GateEvidence, evaluate_gate_evidence

result = evaluate_gate_evidence(
    [
        GateEvidence("filesystem", "passed", "deploy-path"),
        GateEvidence("compose", "passed", "compose-config"),
        GateEvidence("security", "passed", "images"),
        GateEvidence("rollout", "passed", "compose-up"),
        GateEvidence("health", "passed", "primary-container"),
    ]
)
```

`GateEvaluation` contains only `passed`, a bounded `failure_reason`, and
sanitized name/status/target/reason fields suitable for a deployment manifest.
It never accepts command output, secrets, headers, tokens, `.env` paths, or
private-key material. The evaluator does not invoke Docker, mutate a host,
perform a rollout, or replace the existing GitHub Actions workflow; those
operations remain adapter and consumer responsibilities until parity is
proven.
