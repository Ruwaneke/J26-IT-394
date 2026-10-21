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

API documentation is served at `http://localhost:8083/swagger-ui.html`
(OpenAPI JSON at `/v3/api-docs`).

## Persistence

Skill state is stored in two tables, `dev_skill` (current mastery per developer
and CWE) and `skill_event` (an audit trail of every update, with mastery
before and after). The schema is managed by Flyway in
`src/main/resources/db/migration`.

- By default the service uses a file-based H2 database in `./data/`. It runs
  in PostgreSQL mode, needs no setup and keeps data across restarts.
- For PostgreSQL, run with `--spring.profiles.active=postgres` and set
  `DB_URL`, `DB_USERNAME` and `DB_PASSWORD`.
- Tests use an in-memory database (the `test` profile).

## Evaluation

`mvn test` also replays 48 escalation scenarios and writes two reports:

- `target/scenario-report.md` compares V0 (generic), V1 (history counters
  only) and V2 (counters plus skill model). It also lists where the engine
  disagrees with the rubric and includes a +/-25% sensitivity check on the
  mastery parameters.
- `target/tuning-report.md` shows the grid search used to choose policy 1.1.0.
  The search uses the 32 tuning scenarios only.

The scenarios and their expected levels come from the rubric in
`tools/generate_scenarios.py` (run `python tools/generate_scenarios.py` to
regenerate them). The rubric is written independently of the engine. Keep it
fixed when tuning, so the held-out accuracy stays an honest estimate.

| Policy | Held-out V0 | Held-out V1 | Held-out V2 |
|---|---|---|---|
| 1.0.0 (plan starting values) | 9/16 | 10/16 | 10/16 |
| 1.1.0 (tuned) | 10/16 | 11/16 | 13/16 (81%) |
