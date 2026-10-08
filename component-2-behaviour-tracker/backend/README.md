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

Then set your database username and password. You can also use the environment-variable form shown in the template (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`).

> Do not commit `application.properties` with real credentials.

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

## API Endpoints

### Auth
| Method | Path               | Description                                                   |
|--------|--------------------|---------------------------------------------------------------|
| POST   | `/api/auth/github` | Log in with GitHub; finds or creates/links the developer      |

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
| POST   | `/api/behaviour-logs`                        | Create a behaviour log |
| GET    | `/api/behaviour-logs`                        | List all logs          |
| GET    | `/api/behaviour-logs/{id}`                   | Get a log              |
| GET    | `/api/behaviour-logs/developer/{developerId}` | Logs for a developer   |

### Lifecycle History & Analysis
| Method | Path                                                     | Description                              |
|--------|----------------------------------------------------------|------------------------------------------|
| GET    | `/api/lifecycle-history/security-event/{securityEventId}` | Status history of a security event      |
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

## Behaviour Summary

`GET /api/developer-behaviour/{developerId}` returns counts (opened, fixed, ignored, dismissed, reopened), rates (fix, ignore, reopen, high-severity fix), average response time in seconds, repeated vulnerability count, and an overall `behaviourClassification`.

## Error Handling

All errors go through `GlobalExceptionHandler` and return an `ApiErrorResponse`:

- `400` – validation failure
- `404` – resource not found (`ResourceNotFoundException`)
- `409` – duplicate resource (`DuplicateResourceException`)
- `500` – unexpected server error
