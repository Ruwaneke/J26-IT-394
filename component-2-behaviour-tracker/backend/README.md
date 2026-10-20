# Developer Behaviour Tracker – Backend

Spring Boot REST API for **Component 2** of the project. It records security events detected in a developer's code, tracks how developers respond to them (open, fix, ignore, reopen, dismiss), keeps a vulnerability lifecycle history, and produces per-developer behaviour summaries.

## Tech Stack

| Layer      | Technology                                  |
|------------|---------------------------------------------|
| Language   | Java 17                                     |
| Framework  | Spring Boot 3.3.5 (Web, Data JPA, Validation) |
| Database   | PostgreSQL (H2 in-memory for tests)         |
| API docs   | springdoc-openapi 2.6.0 (Swagger UI)        |
| Utilities  | Lombok                                      |
| Build      | Maven                                       |

## Project Structure

```
src/main/java/com/sentinel/tracker/
├── DevBehaviourTrackerApplication.java   # Entry point
├── config/        # JPA auditing configuration
├── controller/    # REST controllers
├── dto/           # Request / response objects
├── entity/        # JPA entities (Developer, SecurityEvent, BehaviourLog, VulnerabilityLifecycleHistory)
├── enums/         # BehaviourAction, SecurityEventStatus, Severity
├── exception/     # Custom exceptions + GlobalExceptionHandler
├── repository/    # Spring Data JPA repositories
└── service/       # Service interfaces and impl/ classes
src/main/resources/
├── application.properties.example   # Configuration template
└── schema.sql                       # PostgreSQL DDL
```

## Getting Started

### Prerequisites

- JDK 17+
- Maven 3.9+
- PostgreSQL 14+

### 1. Create the database

```bash
createdb developer_behavior
psql -d developer_behavior -f src/main/resources/schema.sql   # optional – Hibernate ddl-auto=update also creates tables
```

### 2. Configure the application

```bash
cp src/main/resources/application.properties.example src/main/resources/application.properties
```

The template contains placeholders only. Provide the credentials as environment variables
(`DB_HOST`, `DB_PORT` and `DB_NAME` are optional and default to `localhost`, `5432` and `developer_behavior`):

```bash
export DB_USERNAME=<your-db-user>
export DB_PASSWORD=<your-db-password>
```

or replace the placeholders in your local `application.properties`.

> `application.properties` is listed in `.gitignore` – never commit it or put real credentials in the template.

### 3. Run

```bash
mvn spring-boot:run
```

The API starts on **http://localhost:8080**.

- Swagger UI: http://localhost:8080/swagger-ui.html
- OpenAPI JSON: http://localhost:8080/api-docs
- Health check: `GET /`

### 4. Test

```bash
mvn test
```

Tests use an H2 in-memory database (`src/test/resources/application-test.properties`), so PostgreSQL is not needed to run them.

#### Tests and test reports

The suite (402 test methods in 32 classes, TASKS P1-5 and P1-6) has six groups. The dashboard's
**Quality & Regression Tests** page shows them the same way:

| Group | Main classes | What it checks |
|---|---|---|
| API contract | `*ApiContractTest`, `*ControllerTest` | Every endpoint on the real stack: C1's exact request bodies, validation, invalid JSON, enums, ranges, ISO-8601 timestamps, status codes and the `ApiErrorResponse` format |
| Authentication & authorization | `GitHubAuthApiContractTest`, `GitHubAuthServiceTest` | Sign-in with GitHub's `GET /user` answered by `MockRestServiceServer` (no real token or network): `400`, `401`, `502`, `409`, client identity fields ignored, token never logged; event ownership `403` |
| Lifecycle transitions | `LifecycleTransitionIntegrationTest`, `SecurityEventStatusTest`, `FixVerification*Test` | All 25 status × action pairs, history rows (from, to, time, actor), nothing stored on `409`; claimed versus verified fixes |
| Hash-chain integrity | `LifecycleHistoryVerificationIntegrationTest`, `LifecycleHashChainEdgeCaseIntegrationTest`, `VulnerabilityLifecycleHistoryServiceTest` | Tampering cases, legacy rows (`UNCHAINED`), empty history (`BROKEN`) |
| Database consistency | `WriteFailureRollbackIntegrationTest`, `ConcurrentInteractionIntegrationTest`, `SchemaCompatibilityTest`, `*RepositoryTest` | Rollback when a write fails, concurrent actions on one event, `schema.sql` against the entities |
| Regression | the other service tests | Behaviour analysis, developers, security events |

Every test uses its own H2 rows and deletes them afterwards; no test can reach PostgreSQL.
The hash-chain tests show what the chain detects (edited, deleted, inserted, reordered or
re-hashed entries) and what it does not (deleting the newest entries, or rebuilding the whole
chain with database access). It is tamper-evident, not tamper-proof.

Useful commands:

```bash
mvn test -Dtest=LifecycleTransitionIntegrationTest   # one class
mvn test -Dtest='*ApiContractTest'                    # a group of classes
cd ../frontend && npm run test:report                 # summary + target/quality-report.json
```

Raw results are in `target/surefire-reports/` (JUnit XML). `npm run test:report` turns them
into `target/quality-report.json`. With `npm run dev`, the page at
http://localhost:5173/quality shows the same report, and its **Run test suite** button runs
`mvn -B -ntp test -Dspring.profiles.active=test` here. This is only possible on the local dev
server. It takes no input from the browser, passes no database credentials, allows one run
at a time and stops after 10 minutes. The backend itself has no endpoint that runs tests.

Troubleshooting:

| Symptom | Cause and fix |
|---|---|
| Page says "Test reports are not available here" | The page is served by a production build or `vite preview`. Use `npm run dev`, or the terminal commands above. |
| Page says "No test report yet" | `target/surefire-reports/` is empty. Run the suite. |
| "Maven not found" | `mvn` is not on the `PATH` of the terminal that started `npm run dev`. Install Maven and Java 17, then restart the dev server. |
| "Build failed before the tests ran" | Maven ended without test results, usually a compile error. The page shows Maven's last lines; run `mvn test` in a terminal for the full output. |
| A test fails only on one machine | Check the Java version (`java -version` must be 17+). The tests do not depend on PostgreSQL, the network or the time zone. |
| Old results still shown | The page reads whatever is in `target/surefire-reports/`. A run from the page clears it first; after a terminal run, select **Refresh results**. |
| Results mix two runs | `mvn test -Dtest=…` only rewrites the reports of the classes it ran. Run the whole suite (or `mvn clean test`) before reading the report. |

## API Endpoints

### Auth
| Method | Path               | Description                                                   |
|--------|--------------------|---------------------------------------------------------------|
| POST   | `/api/auth/github` | Log in with GitHub; finds or creates/links the developer      |

Request body: `{"githubAccessToken": "<token from the VS Code GitHub session>"}`.
The backend verifies the token with GitHub's `GET /user` and takes the developer's
GitHub id, login and email from that response; any identity fields sent by the client
are ignored. Responses: `200` developer returned, `400` missing token, `401` token
rejected by GitHub, `409` login already linked to a different GitHub account,
`502` GitHub API unavailable. The GitHub API base URL can be changed with
`github.api.base-url` (default `https://api.github.com`).

### Developers
| Method | Path                   | Description         |
|--------|------------------------|---------------------|
| POST   | `/api/developers`      | Create a developer  |
| GET    | `/api/developers`      | List all developers |
| GET    | `/api/developers/{id}` | Get a developer     |

### Security Events
| Method | Path                                          | Description                    |
|--------|-----------------------------------------------|--------------------------------|
| POST   | `/api/security-events`                        | Record a detected vulnerability |
| GET    | `/api/security-events`                        | List all events                |
| GET    | `/api/security-events/{id}`                   | Get an event                   |
| GET    | `/api/security-events/developer/{developerId}` | Events for a developer         |

### Developer Interactions
| Method | Path                                                         | Description                      |
|--------|--------------------------------------------------------------|----------------------------------|
| POST   | `/api/developer-interactions`                                 | Record an action on an event     |
| GET    | `/api/developer-interactions`                                | List all interactions            |
| GET    | `/api/developer-interactions/{id}`                           | Get an interaction               |
| GET    | `/api/developer-interactions/developer/{developerId}`        | Interactions by developer        |
| GET    | `/api/developer-interactions/security-event/{securityEventId}` | Interactions for an event      |

### Behaviour Logs
| Method | Path                                         | Description            |
|--------|----------------------------------------------|------------------------|
| POST   | `/api/behaviour-logs`                        | **Deprecated** – use `POST /api/developer-interactions` |
| GET    | `/api/behaviour-logs`                        | List all logs          |
| GET    | `/api/behaviour-logs/{id}`                   | Get a log              |
| GET    | `/api/behaviour-logs/developer/{developerId}` | Logs for a developer   |

`POST /api/developer-interactions` is the single write path for developer actions.
The deprecated `POST /api/behaviour-logs` still works but is processed by the same
interaction logic (status update, lifecycle history, response time), requires
`securityEventId`, and responds with `Deprecation: true` and a `Link` header pointing to
the replacement. Both APIs read and write the same `behaviour_logs` table, so the GET
endpoints above also return actions recorded as developer interactions.

### Lifecycle History & Analysis
| Method | Path                                                     | Description                              |
|--------|----------------------------------------------------------|------------------------------------------|
| GET    | `/api/lifecycle-history/security-event/{securityEventId}` | Status history of a security event      |
| GET    | `/api/lifecycle-history/security-event/{securityEventId}/verify` | Check the history's hash chain: `VALID`, `BROKEN` or `UNCHAINED` |
| GET    | `/api/developer-behaviour/{developerId}`                 | Behaviour summary and classification     |

## Example Requests

Create a developer:
```bash
curl -X POST http://localhost:8080/api/developers \
  -H "Content-Type: application/json" \
  -d '{"developerIdentifier": "jdoe"}'
```

Record a security event:
```bash
curl -X POST http://localhost:8080/api/security-events \
  -H "Content-Type: application/json" \
  -d '{
    "developerId": 1,
    "vulnerabilityType": "SQL_INJECTION",
    "severity": "HIGH",
    "fileName": "UserDao.java",
    "lineNumber": 42,
    "message": "Unsanitised input in query"
  }'
```

Record a developer action:
```bash
curl -X POST http://localhost:8080/api/developer-interactions \
  -H "Content-Type: application/json" \
  -d '{"securityEventId": 1, "developerId": 1, "action": "FIX", "source": "IDE"}'
```

## Enums

| Enum                  | Values                                          |
|-----------------------|-------------------------------------------------|
| `Severity`            | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`             |
| `BehaviourAction`     | `OPEN`, `IGNORE`, `FIX`, `REOPEN`, `DISMISS`    |
| `SecurityEventStatus` | `DETECTED`, `OPENED`, `IGNORED`, `REOPENED`, `FIXED` |
| `FixVerificationStatus` | `CLAIMED`, `VERIFIED`, `STILL_VULNERABLE` (FIX interactions only) |

## Vulnerability Lifecycle

Creating a security event records its first lifecycle history entry (`null` → `DETECTED`, changed
by `SYSTEM`). Each developer action then maps to a status, and every status change adds one entry:

| Action              | New status |
|---------------------|------------|
| `OPEN`              | `OPENED`   |
| `FIX`               | `FIXED`    |
| `IGNORE`, `DISMISS` | `IGNORED`  |
| `REOPEN`            | `REOPENED` |

| From       | Allowed next statuses          |
|------------|--------------------------------|
| `DETECTED` | `OPENED`, `FIXED`, `IGNORED`   |
| `OPENED`   | `FIXED`, `IGNORED`             |
| `IGNORED`  | `OPENED`, `FIXED`, `REOPENED`  |
| `REOPENED` | `OPENED`, `FIXED`, `IGNORED`   |
| `FIXED`    | `REOPENED`                     |

An action that would make any other change (for example `OPEN` on a `FIXED` event) is rejected with
`409 Conflict` and nothing is recorded. An action that keeps the current status (for example a second
`OPEN`) is still logged but adds no history entry.

### Claimed and verified fixes

A `FIX` is a **claim**, not proof. C1 sends it when the developer uses the Fix code action,
which shows the secure example; nothing re-checks the code. The event still moves to `FIXED`
(the lifecycle records what the developer reported), and the interaction carries
`fixVerification`:

| Value | Meaning |
|---|---|
| `CLAIMED` | The developer reported a fix; nothing confirmed it. Every FIX is `CLAIMED` today. |
| `VERIFIED` | A verification source confirmed the vulnerability is gone. |
| `STILL_VULNERABLE` | A verification source found it still present. The claim is still accepted (`201`). |

Other actions have `fixVerification: null`. The value comes from `FixVerificationService`. Until
C1 reports whether a finding is still present after a fix, the only implementation
(`ClaimOnlyFixVerificationService`) returns `CLAIMED`; tests replace it with controlled mock
results. FIX logs written before this existed are marked `CLAIMED` by `schema.sql`.

### Tamper-evident history

The history entries of each event form a SHA-256 hash chain: every entry stores `prevHash` (the
previous entry's hash) and `entryHash` (a hash over `prevHash` and its own fields). If anyone
later edits, deletes or reorders an entry in the database, `GET
/api/lifecycle-history/security-event/{id}/verify` reports `BROKEN` and the first entry that
fails. Entries written before the chain existed have no hashes and are reported as `UNCHAINED`.
This is tamper-evident, not tamper-proof: someone with database access who knows the algorithm
can rebuild the chain, and deleting the newest entries is not detected. Details: TECHNICAL_OVERVIEW §5.5.

## Behaviour Summary

`GET /api/developer-behaviour/{developerId}` returns counts (opened, fixed, ignored, dismissed, reopened), rates (fix, ignore, reopen, high-severity fix), average response time in seconds, repeated vulnerability count, and an overall `behaviourClassification`.

`fixedCount` and `fixRate` count **claimed** fixes (any `FIX`), and the classification uses them. `verifiedFixCount` and `verifiedFixRate` count only events with a `VERIFIED` fix, so they stay `0` until a verification source exists.

## Error Handling

All errors go through `GlobalExceptionHandler` and return an `ApiErrorResponse`:

- `400` – validation failure
- `404` – resource not found (`ResourceNotFoundException`)
- `409` – duplicate resource (`DuplicateResourceException`) or invalid lifecycle transition (`InvalidStatusTransitionException`)
- `500` – unexpected server error
