# Intelligent Feedback Engine

Component 3 is developed as a standalone Spring Boot prototype before full
system integration. It consumes mock security-event data from Component 1 and
mock behaviour-history data from Component 2.

## Build and test

From this directory, run:

```text
mvn test
```

The service is configured to use port `8083` when it is started with
`mvn spring-boot:run`.

The current prototype includes mock security-event and behaviour-history
models, severity scoring, and behaviour-aware feedback escalation. Repeated
ignored warnings increase feedback severity, while consistent fixes reduce
severity without crossing the `INFO` or `CRITICAL` boundaries.

It also provides secure-coding recommendation templates for each supported
vulnerability category, including practical guidance and secure examples.

For a browser demonstration using mock data, start the service and open
`http://localhost:8083/`. The page shows the original score, behaviour-based
escalation, and SQL-injection recommendation. The raw JSON is available at
`http://localhost:8083/api/demo`. The demo also shows the monitored file, the
vulnerable code, the detected error, and a corrected secure version.

## Adaptive decision API (Plan A)

The `/api/v1` endpoints implement the per-developer skill model and priority
score described in the Adaptive Security Coach plan:

- `POST /api/v1/feedback/decide`: takes a security event and the developer's
  history, and returns feedback level L1-L4, a score breakdown, the reasons,
  any override or relief adjustments, the policy version and a static template.
- `GET /api/v1/skills/{devHash}`: returns mastery per CWE, with time decay applied.
- `POST /api/v1/skills/{devHash}/events`: records a `FIX`, `IGNORE`, `REPEAT`
  or `REOPEN` outcome.

All weights, level thresholds, mastery parameters and hard overrides are in
`src/main/resources/policy.yaml`. To try different values without
recompiling, start the service with
`--spring.config.additional-location=file:./my-policy.yaml`.

Example request:

```json
{
  "event":   {"eventId": "e-1021", "cwe": "CWE-89", "severity": "HIGH",
              "language": "java", "line": 42, "snippet": "..."},
  "history": {"devHash": "d-7f3a", "repeats30d": 3, "ignored30d": 2,
              "fixed30d": 1, "reopened30d": 0, "lastSimilarDaysAgo": 2}
}
```

Skill state is held in memory for now. The older `scoring` package is kept as
the counter-only baseline (V1) for the ablation study.
