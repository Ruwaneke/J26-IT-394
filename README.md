# Sentinel

## Intelligent, Behaviour-Aware Secure Coding Environment

Sentinel is a four-component research system that detects insecure coding
patterns, records developer behaviour, generates adaptive security feedback,
and presents research results through a dashboard.

The research goal is to evaluate whether personalised, behaviour-aware
security feedback can improve secure coding behaviour over time.

## Project status

The repository is being developed incrementally by component. The current
status is:

| Component | Responsibility | Current status |
|---|---|---|
| Component 1 - Sentinel VS Code Extension | Detect vulnerabilities and provide real-time editor feedback | Initial implementation available |
| Component 2 - Developer Behaviour Tracker | Receive security events and maintain behaviour history | Backend structure created; implementation is pending |
| Component 3 - Intelligent Feedback Engine | Score severity, escalate feedback and generate personalised recommendations | Standalone Spring Boot setup verified |
| Component 4 - Analytics Dashboard | Visualise behaviour and research outcomes | Frontend and backend structure created; implementation is pending |



## System architecture

```text
┌──────────────────────────┐
│ Component 1              │
│ Sentinel VS Code         │
│ Extension                │
│                          │
│ Detects SQL injection,   │
│ XSS and hardcoded        │
│ secrets                  │
└────────────┬─────────────┘
             │ security events
             ▼
┌──────────────────────────┐
│ Component 2              │
│ Developer Behaviour      │
│ Tracker                  │
│                          │
│ Stores developer actions │
│ and behaviour history    │
└────────────┬─────────────┘
             │ security events +
             │ behaviour history
             ▼
┌──────────────────────────┐
│ Component 3              │
│ Intelligent Feedback     │
│ Engine                   │
│                          │
│ Scores severity, applies │
│ escalation rules and     │
│ creates recommendations  │
└────────────┬─────────────┘
             │ feedback and analytics data
             ▼
┌──────────────────────────┐
│ Component 4              │
│ Analytics & Web          │
│ Dashboard                │
│                          │
│ Displays developer and   │
│ research results         │
└──────────────────────────┘
```

## Repository structure

```text
J26-IT-394/
├── component-2-behaviour-tracker/
│   ├── backend/                    # Component 2 backend foundation
│   └── database/                   # Component 2 database areas
├── component-3-feedback-engine/
│   ├── src/main/java/              # Spring Boot application
│   ├── src/test/java/               # Component 3 tests
│   ├── ai-model/                   # Planned AI/model layer
│   ├── api/                        # Planned REST API layer
│   ├── recommendation/             # Planned recommendation layer
│   ├── services/                   # Planned engine services
│   ├── DEVELOPMENT_PLAN.md         # October 12-20 milestone schedule
│   └── pom.xml                     # Maven project configuration
├── component-4-dashboard/
│   ├── backend/                    # Planned analytics backend
│   └── frontend/                   # Planned dashboard frontend
├── database/                       # Shared database migration/schema areas
├── deployment/                     # Deployment configuration areas
├── docs/                           # API, architecture and research docs
├── sentinel/                       # Component 1 VS Code extension
├── shared/                         # Shared models, constants and contracts
└── testing/                        # Integration, security and unit test areas
```

## Component 1: Sentinel VS Code Extension

Component 1 provides real-time security analysis while developers write code.
The current implementation includes:

- SQL injection detection
- Cross-site scripting (XSS) detection
- Hardcoded secret detection
- Red diagnostics and Problems panel integration
- Hover explanations and secure examples
- `Explain`, `Fix` and `Ignore` code actions
- Security events sent to the behaviour tracker
- Security alert terminal output
- VS Code security dashboards
- Developer, supervisor and administrator views
- Local developer/project data stores
- AI-enhanced analysis support and learning data structures

### Run Component 1

```text
cd sentinel
npm install
npm run compile
```

Open the `sentinel` folder in VS Code and press **F5** to start the Extension
Development Host.

The extension settings include:

| Setting | Default | Description |
|---|---|---|
| `sentinel.enabled` | `true` | Enable or disable analysis |
| `sentinel.debounceMs` | `400` | Delay before analysis |
| `sentinel.backendUrl` | `http://localhost:3000` | Behaviour tracker URL |
| `sentinel.developerId` | `DEV001` | Developer identifier |

Component 1 sends security events using the shared contract represented by
`SecurityFinding` and the security-event API.

## Component 2: Developer Behaviour Tracker

Component 2 is responsible for receiving security events and recording
developer behaviour history. Its current repository contribution is the
backend foundation and package structure:

- Spring Boot backend project location
- Analysis, configuration, controller, DTO, entity, enum, exception,
  repository and service package areas
- Resource and test locations
- Database migration, schema and sample-data locations

The implementation of the event receiver, behaviour-history persistence and
REST endpoints is still pending.

## Component 3: Intelligent Feedback Engine

Component 3 will transform security events and behaviour history into
adaptive feedback. Its planned core capabilities are:

1. Model security events, behaviour history and feedback responses.
2. Calculate vulnerability severity using explicit scoring rules.
3. Escalate or reduce feedback according to severity and behaviour history.
4. Apply secure-coding recommendation templates.
5. Generate personalised recommendations.
6. Integrate the engine into one standalone service.
7. Expose the service through a tested REST API.


The current verified test result is one Spring context test passing with zero
failures and zero errors. The severity engine, escalation engine,
recommendation generator and REST endpoints are scheduled for the remaining
milestone days.

## Component 4: Analytics and Web Dashboard

Component 4 will provide the research and monitoring interface. The current
structure contains planned areas for:

- Analytics processing
- Backend controllers
- Reports
- Frontend charts
- Reusable frontend components
- Dashboard pages
- Frontend services

The dashboard implementation will be connected after the event, behaviour and
feedback contracts are stable.

## Shared project areas

The repository also reserves shared locations for:

- API contracts
- Shared constants
- Shared models
- Database schema, migrations and sample data
- Deployment configuration, Docker and Nginx
- API, architecture and research documentation
- Unit, integration and security testing

These areas currently contain project structure placeholders and will be
implemented as the component contracts mature.

## Development principles

- Develop and verify each component independently.
- Keep Component 3 standalone until its core engine works.
- Use mock Component 1 and Component 2 data during Component 3 development.
- Test each feature before marking it complete.
- Prioritise severity scoring, escalation, personalised recommendations and
  the REST API over optional features.
- Keep component-specific changes inside the relevant component directory.
- Commit verified daily progress to the relevant Git branch.
- Confirm before committing and pushing milestone work.

This repository is an academic research project for the J26-IT-394 team.
