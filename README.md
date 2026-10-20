# Sentinel

**Real-Time Intelligent Security Monitoring Tool with Developer Behaviour Analysis**
Project J26-IT-394 · IT4010 Research Project, 2026 · Specialisation: Information Technology ·
Research group: Information Assurance & Security (IAS)

A developer writes code in VS Code. Sentinel flags insecure patterns such as SQL injection,
cross-site scripting and hardcoded secrets on the line where they appear, while the code is
being typed. It then records what the developer does about each warning: fixes it, ignores
it, dismisses it, or lets the same mistake come back. From that history it raises or lowers
how strongly it warns each developer and shows how their security habits change over time.

The research question is whether real-time, behaviour-aware security feedback leads to
measurably better secure-coding behaviour over time.

---

## Contents

1. [The problem](#1-the-problem)
2. [Existing solutions and their limits](#2-existing-solutions-and-their-limits)
3. [What Sentinel does](#3-what-sentinel-does)
4. [How the system works](#4-how-the-system-works)
5. [The four components](#5-the-four-components)
6. [Shared interface contracts](#6-shared-interface-contracts)
7. [Data, privacy and ethics](#7-data-privacy-and-ethics)
8. [Technology stack](#8-technology-stack)
9. [Repository layout and branches](#9-repository-layout-and-branches)
10. [Getting started](#10-getting-started)
11. [Project status](#11-project-status)
12. [Team](#12-team)
13. [References](#13-references)

---

## 1. The problem

Software vulnerabilities remain a leading cause of cyberattacks, data breaches and financial
loss. Plenty of security testing tools exist, yet security flaws still go unresolved and
reach production. The tools are not the only gap. The people using them are another.

- **Alert fatigue.** Developers working to tight deadlines face many security warnings.
  Warnings get ignored and fixes get delayed.
- **Detection without understanding.** ML and Graph Neural Network detectors have improved
  how accurately vulnerable code is found. They say little about how developers *respond*
  to a warning.
- **Behaviour is not tracked.** IDE activity has been studied to understand general coding
  patterns, but security-specific behaviour has received little attention. That includes
  ignored warnings, repeated vulnerabilities and improvement over time.
- **No central view.** Security teams can see vulnerabilities but not the behaviour that
  keeps producing them, so they cannot give targeted guidance.
- **Generic feedback.** Existing feedback gives every developer the same advice, whatever
  their history.
- **Static dashboards.** Current dashboards report vulnerability counts and statistics.
  They give little support for behaviour analytics or risk prediction.

**Who is affected:** developers (repeated mistakes, noisy tooling), security and
engineering leads (recurring issues with no visible cause), and organisations (risk that
reaches production).

## 2. Existing solutions and their limits

| Approach | Examples | Limitation |
|---|---|---|
| Static analysis and security scanners | SonarQube, Snyk, Checkmarx, GitHub Advanced Security | Find and report weaknesses, but do not record how each developer responds to them. |
| ML / GNN vulnerability detectors | Structure-aware and heterogeneous GNN detectors; offline GNN plugins with LLM explanations | Improve detection accuracy; developer behaviour is out of scope. |
| IDE behaviour studies | 1000-hour industrial study of developer behaviour; eye-tracking + IDE action studies; cloud-IDE behaviour studies | Characterise general coding activity, not responses to security warnings. |
| Immediate in-IDE security feedback | Research prototypes for security-relevant code | Same message for every developer; no escalation from history. |
| Security dashboards | Vendor and research dashboards | Show vulnerability counts; little behaviour analytics or forecasting. |

None of these tracks ignored alerts, repeated mistakes, delayed fixes and long-term
improvement together, and none adapts its feedback to an individual developer.

## 3. What Sentinel does

Sentinel is four research components that form one pipeline: detection feeds tracking,
tracking informs feedback, and all three feed analytics.

| | Component | What it solves |
|---|---|---|
| **C1** | Real-Time Code Detection (Sentinel VS Code extension) | Finds insecure patterns while code is written, shows them in the editor, and turns every detection and developer action into a structured event. |
| **C2** | Developer Behaviour Tracker | The system's memory. Records each warning's full lifecycle and how the developer responded, and builds a behaviour summary and classification per developer. |
| **C3** | Intelligent Feedback Engine | The decision layer. Scores each issue's severity from the event and the developer's history, escalates warnings that keep being ignored, and attaches secure-coding guidance. |
| **C4** | Analytics and Dashboard | The research evidence layer. Measures improvement over time, forecasts behaviour, classifies developers into research risk profiles, runs correlation analysis and produces a research summary report. |

## 4. How the system works

### 4.1 A detection and a developer response

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant C1 as C1 Sentinel extension
    participant GH as GitHub API
    participant C2 as C2 Behaviour Tracker
    participant DB as PostgreSQL
    Dev->>C1: Sign in with GitHub (VS Code auth)
    C1->>C2: POST /api/auth/github {githubAccessToken}
    C2->>GH: GET /user (verify token)
    GH-->>C2: id, login, email
    C2->>DB: find / link / create developer
    C2-->>C1: developer (backend developerId)
    Dev->>C1: types code
    Note over C1: 400 ms debounce, rule engine, confidence filter
    C1-->>Dev: red underline, Problems panel, hover
    C1->>C2: POST /api/security-events
    C2->>DB: security_events (DETECTED) + lifecycle entry (SYSTEM)
    Dev->>C1: Explain / Fix / Ignore
    C1->>C2: POST /api/developer-interactions {action}
    C2->>DB: behaviour_logs + new status + lifecycle entry
```

### 4.2 The full pipeline

```mermaid
flowchart LR
    Code[Code being typed] --> C1[C1 Detection<br/>VS Code extension]
    C1 -->|security events,<br/>developer actions| C2[C2 Behaviour Tracker<br/>Spring Boot + PostgreSQL]
    C2 -->|events +<br/>behaviour history| C3[C3 Feedback Engine<br/>Spring Boot]
    C3 -->|scored, escalated<br/>feedback| C1
    C2 -->|event stream| C4[C4 Analytics<br/>Python pipeline]
    C4 -->|analytics.json| D[C4 Dashboard<br/>React in VS Code webview]
    C2 --> D2[C2 Dashboard<br/>React web app]
```

### 4.3 The vulnerability lifecycle (C2)

Every security event moves through a fixed set of statuses. Each developer action maps to a
target status, and only the transitions below are accepted.

```mermaid
stateDiagram-v2
    [*] --> DETECTED: event created (SYSTEM)
    DETECTED --> OPENED: OPEN
    DETECTED --> FIXED: FIX
    DETECTED --> IGNORED: IGNORE / DISMISS
    OPENED --> FIXED: FIX
    OPENED --> IGNORED: IGNORE / DISMISS
    IGNORED --> OPENED: OPEN
    IGNORED --> FIXED: FIX
    IGNORED --> REOPENED: REOPEN
    REOPENED --> OPENED: OPEN
    REOPENED --> FIXED: FIX
    REOPENED --> IGNORED: IGNORE / DISMISS
    FIXED --> REOPENED: REOPEN
```

### 4.4 Who talks to whom

| Component | Takes in | Gives out |
|---|---|---|
| **C1** | Source code as it is typed; developer clicks (Explain, Fix, Ignore); GitHub sign-in | `SecurityFinding` objects; security events and developer actions sent to C2; requests to C3 for enriched feedback |
| **C2** | Security events and developer actions from C1; GitHub access token | Stored events, behaviour logs, lifecycle history; per-developer behaviour summary and classification |
| **C3** | A security event plus the developer's behaviour history | A severity score and level, adjusted for history, with a recommendation template |
| **C4** | A stream of events in the C4 event schema (today: simulated) | `analytics.json`: trends, forecasts, risk profiles, correlations, recommendations; research summary report |

## 5. The four components

### C1 · Real-Time Code Detection: the Sentinel VS Code Extension

**Owner:** M H S Perera (IT23163218) · **Folder:** [`sentinel/`](sentinel/) ·
**Branches:** `main`, `hishen_dev` · **Runs in:** VS Code Extension Host (no port)

**Problem.** Most security checks run after code is written: in CI, in review or in a
scheduled scan. By then the developer has moved on, and the warning arrives out of context.

**Objective.** Monitor code changes in real time, detect insecure patterns, show warnings
in the editor, and send every detection to the backend as structured data that the rest of
the system builds on.

**Novelty.** Detection happens *while the developer types*, not after development. Every
warning and every response becomes a structured event, so C1 is both the user-facing tool
and the research data source.

**How it works.**

1. **Trigger.** On every document change, after a debounce (`sentinel.debounceMs`, 400 ms
   by default), the active file is passed to the analyser. The extension activates on
   `onStartupFinished`.
2. **Rule engine.** [`SecurityAnalyzer`](sentinel/src/analyzer/securityAnalyzer.ts) runs
   every registered rule over the text. Each rule is a list of regular expressions with an
   id, a severity, a message and context keywords that raise confidence. One finding is
   kept per vulnerability, not one per matching pattern.

   | Rule | Patterns | Covers |
   |---|---|---|
   | [`sqlInjectionRule.ts`](sentinel/src/rules/sqlInjectionRule.ts) | 17 | String-concatenated `SELECT`/`INSERT`/`UPDATE`/`DELETE`, `LIKE` and `ORDER BY` injection, JS template literals, stored-procedure building, several languages and frameworks |
   | [`xssRule.ts`](sentinel/src/rules/xssRule.ts) | 18 | `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string `setTimeout`, React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`, server-side templates |
   | [`hardcodedSecretRule.ts`](sentinel/src/rules/hardcodedSecretRule.ts) | 22 | Generic API keys, passwords and secret variables; AWS keys; OpenAI/Anthropic/Google AI keys; cloud, CI/CD, database and payment-provider tokens; SSH/PEM private keys. Vendor-specific patterns are CRITICAL, generic ones HIGH |

3. **Confidence.** Each finding carries a confidence score from 0.0 to 1.0. Context such as
   `req.body` or user-id-like variable names raises it. Findings below
   `sentinel.minConfidence` (0.7 by default) are hidden.
4. **Learning layer.** [`AIEnhancedAnalyzer`](sentinel/src/ai/aiEnhancedAnalyzer.ts) and
   [`DeveloperLearningStore`](sentinel/src/ai/developerLearningStore.ts) post-filter the raw
   findings per developer. They do three things:
   - suppress types the developer has repeatedly marked as false positives;
   - skip code-snippet hashes already marked as false positives;
   - adjust per-rule confidence.

   With `sentinel.enableAI` on, findings are also sent to the feedback engine
   (`POST {sentinel.ifeUrl}/api/feedback/request`), which returns AI-generated explanations
   and fixes. The real-time underline does not wait for this call.
5. **Presentation.** [`DiagnosticManager`](sentinel/src/diagnostics/diagnosticManager.ts)
   shows the findings in the editor:
   - a red underline on the vulnerable code and an entry in the Problems panel;
   - a hover with an explanation and a secure example
     ([`vulnerabilityMetadata.ts`](sentinel/src/diagnostics/vulnerabilityMetadata.ts));
   - a lightbulb with **Explain**, **Fix** and **Ignore** code actions.

   [`ContextualExplainer`](sentinel/src/diagnostics/contextualExplainer.ts) explains why
   *this* line is vulnerable and generates a transformed fix. A "Sentinel Security Alert"
   terminal echoes the findings.
6. **Reporting to C2.** [`SecurityEventClient`](sentinel/src/events/securityEventClient.ts)
   sends detections and developer actions to C2:
   - It queues events (up to 500) and sends them in batches every second, in order, so a
     detection always reaches C2 before any action on it.
   - A failed send is retried up to 3 times, with a 5-second timeout per request.
   - Events wait in the queue until the developer's backend `developerId` is known from
     GitHub sign-in.
   - Findings are tracked by file + line + type, so re-analysing a file does not create
     duplicates.
7. **Identity and roles.** [`AuthManager`](sentinel/src/auth/authManager.ts) offers two
   ways to sign in:
   - **GitHub OAuth** through VS Code's built-in auth provider (primary). The session is
     refreshed silently on activation.
   - **Username and password** checked against SHA-256 hashes, for supervisors and
     administrators without GitHub.

   There are three roles: `developer`, `supervisor` and `administrator`.
8. **In-editor dashboards** (webviews):
   - [Login](sentinel/src/webview/loginView.ts): GitHub sign-in first, password second.
   - [Developer](sentinel/src/webview/developerDashboard.ts): security score, live
     findings, breakdown by vulnerability type, assigned shifts, shift reports.
   - [Supervisor](sentinel/src/webview/supervisorDashboard.ts): team overview, projects,
     shifts, per-developer reports, developer roster.
   - [Administrator](sentinel/src/webview/adminDashboard.ts): users, system statistics,
     adding and removing users, configuration.
9. **Local stores** in `sentinel/src/data/` (JSON files):
   - per-developer vulnerability records (`<id>_vulnerability_records.json`);
   - learning profiles (`<id>_learning.json`);
   - users, projects, shifts and shift sessions
     ([`projectStore.ts`](sentinel/src/data/projectStore.ts)).

**Commands.** `Sentinel: Show Security Dashboard` · `Sentinel: Analyze Current File` ·
`Sentinel: Show Output Channel`.

**Settings.**

| Setting | Default | Purpose |
|---|---|---|
| `sentinel.enabled` | `true` | Turn real-time analysis on or off |
| `sentinel.debounceMs` | `400` | Delay after a change before analysing (ms) |
| `sentinel.backendUrl` | `http://localhost:8080` | C2 Behaviour Tracker URL |
| `sentinel.developerId` | `DEV001` | Fallback id for local learning data only; C2 uses the GitHub identity |
| `sentinel.enableAI` | `false` | Send findings to the feedback engine for AI-generated explanations |
| `sentinel.ifeUrl` | `http://localhost:4000` | Feedback engine URL |
| `sentinel.minConfidence` | `0.7` | Hide findings below this confidence |

**In progress on `hishen_dev`** (not yet merged):
- an OWASP Top 10 rule set built on a shared `patternEngine.ts`. Its rules cover
  injection, broken access control, cryptographic failures, insecure design, security
  misconfiguration, vulnerable components, authentication failures, integrity failures,
  logging failures and SSRF, alongside the existing SQLi, XSS and secrets rules;
- a Neon serverless PostgreSQL store (`pg`) that replaces the local JSON files. It holds
  users, vulnerability records with root cause and remediation, audit logs, projects and
  shifts, and falls back to offline storage when the database cannot be reached;
- a deliberately vulnerable `test_project/` (Express) with an automated check that every
  rule fires;
- a loading screen for sign-in, and a fresh GitHub session after an explicit sign-out.

**Tech stack.** TypeScript 5.4 · VS Code Extension API (engine ^1.85.0) · `node-fetch` 3 ·
ESLint 8 with typescript-eslint 8 · `vsce` for packaging · (`hishen_dev`: `pg` 8 + Neon
PostgreSQL).

---

### C2 · Developer Behaviour Tracker

**Owner:** R S D Sulakshana (IT23249752) ·
**Folder:** [`component-2-behaviour-tracker/`](component-2-behaviour-tracker/) ·
**Branch:** `feature/component-2-backend-foundation` (older snapshot on `dev`) ·
**Ports:** API 8080, dashboard 5173

**Problem.** A warning is only half the data. Without a record of what the developer did
next, there is no way to tell a developer who fixes everything from one who dismisses every
SQL injection warning, or to see the same mistake return.

**Objective.** Receive security events from C1, store the alert type, file, line,
timestamp and the developer's response, track whether warnings are fixed, ignored or
repeated, and build behaviour summaries from that history.

**Novelty.** It records more than alerts. It models each vulnerability's lifecycle with
enforced status transitions and measures response times. From that it produces an
explainable behaviour classification per developer, which turns a linter into a research
instrument.

**Data model** (PostgreSQL; DDL in
[`schema.sql`](component-2-behaviour-tracker/backend/src/main/resources/schema.sql)):

| Table | Holds | Key columns |
|---|---|---|
| `developers` | One row per developer, linked to GitHub | `developer_identifier` (unique), `github_id` (unique), `github_username`, `email` |
| `security_events` | One row per detected vulnerability | `developer_id`, `vulnerability_type`, `severity`, `file_name`, `line_number`, `message`, `detected_at`, `current_status` |
| `behaviour_logs` | One row per developer action | `developer_id`, `security_event_id`, `action_type`, `timestamp`, `time_since_detection_seconds`, `session_id`, `source`, `context_metadata` |
| `vulnerability_lifecycle_history` | One row per status change, hash-chained per event | `security_event_id`, `previous_status`, `new_status`, `changed_at`, `changed_by`, `prev_hash`, `entry_hash` |

All tables have audit timestamps (JPA auditing) and indexes on the developer, event, time,
type, severity and status columns. Deleting a developer cascades to their events; deleting
an event sets its behaviour logs' event reference to null.

**Enums.**

| Enum | Values |
|---|---|
| `Severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `BehaviourAction` | `OPEN`, `IGNORE`, `FIX`, `REOPEN`, `DISMISS` |
| `SecurityEventStatus` | `DETECTED`, `OPENED`, `IGNORED`, `REOPENED`, `FIXED` |

**How a developer action is processed**
([`DeveloperInteractionServiceImpl`](component-2-behaviour-tracker/backend/src/main/java/com/sentinel/tracker/service/impl/DeveloperInteractionServiceImpl.java)),
all in one transaction:

1. Load the developer, and load the security event with a **pessimistic write lock** so
   concurrent actions on the same event are serialised.
2. **Ownership check.** Only the developer who owns the event may act on it (`403`
   otherwise).
3. Map the action to a target status: `OPEN → OPENED`, `FIX → FIXED`,
   `IGNORE`/`DISMISS → IGNORED`, `REOPEN → REOPENED`.
4. **Validate the transition** against the lifecycle in [section 4.3](#43-the-vulnerability-lifecycle-c2).
   Any other change is rejected with `409` and nothing is stored. An action that keeps the
   current status (a second `OPEN`, or `DISMISS` after `IGNORE`) is not a transition: it is
   accepted.
5. Compute `time_since_detection_seconds` and save the behaviour log. A `FIX` is stored as
   a claim with `fixVerification` (`CLAIMED` unless a verification source says `VERIFIED`
   or `STILL_VULNERABLE`; no source exists yet, so it is `CLAIMED`). If the status
   changes, update the event's status and append a lifecycle history entry with
   `changed_by` = the developer; a same-status action adds no history entry.

Creating a security event writes its first lifecycle entry (`null → DETECTED`, changed by
`SYSTEM`) in the same transaction.

**Behaviour analysis**
([`BehaviourAnalysisServiceImpl`](component-2-behaviour-tracker/backend/src/main/java/com/sentinel/tracker/service/impl/BehaviourAnalysisServiceImpl.java)).
`GET /api/developer-behaviour/{developerId}` returns:

- **Counts:** opened, fixed, ignored, dismissed, reopened. Each counts *distinct* events
  owned by the developer, so repeated actions on one event count once and every rate stays
  within 0–100%.
- **Rates** (percent of the developer's events, one decimal):
  - fix rate (claimed fixes), and separately the verified fix count and rate;
  - ignore rate (ignored or dismissed, counted once per event);
  - reopen rate;
  - high-severity fix rate over HIGH and CRITICAL events (`null` if the developer has
    none).
- **Average response time** in seconds, and the **repeated vulnerability count** (the
  number of vulnerability types that appear more than once).
- **Classification**, from explainable rules applied in this order:

  | Classification | Rule |
  |---|---|
  | `INSUFFICIENT_DATA` | fewer than 3 events or fewer than 3 actions |
  | `SECURITY_RESPONSIVE` | fix rate ≥ 80%, high-severity fix rate ≥ 80% (or not applicable), ignore rate < 20% |
  | `SECURITY_AT_RISK` | ignore rate ≥ 40%, or high-severity fix rate < 50% |
  | `RECURRING_SECURITY_BEHAVIOUR` | reopen rate ≥ 30%, or 3 or more repeated vulnerability types |
  | `SECURITY_NEUTRAL` | none of the above |

**GitHub sign-in** ([`GitHubAuthServiceImpl`](component-2-behaviour-tracker/backend/src/main/java/com/sentinel/tracker/service/impl/GitHubAuthServiceImpl.java)).
The client sends only a GitHub access token. C2 verifies it with GitHub's `GET /user` and
takes the id, login and email from that response, never from the client. It then looks the
developer up in three steps:

1. Find the developer by verified GitHub id, and refresh their profile.
2. Otherwise, link a legacy record whose identifier equals the login. If that record is
   already linked to a different GitHub account, return `409`.
3. Otherwise, create a new developer.

No database connection is held while waiting for GitHub.

**REST API** (Swagger UI at `/swagger-ui.html`, OpenAPI JSON at `/api-docs`, health check
`GET /`):

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/github` | Sign in with a GitHub token; find, link or create the developer |
| POST · GET | `/api/developers` | Create · list developers |
| GET | `/api/developers/{id}` | Get one developer |
| POST · GET | `/api/security-events` | Record a detection · list all |
| GET | `/api/security-events/{id}` | Get one event |
| GET | `/api/security-events/developer/{developerId}` | Events for a developer |
| POST · GET | `/api/developer-interactions` | Record an action (the single write path) · list all |
| GET | `/api/developer-interactions/{id}` | Get one interaction |
| GET | `/api/developer-interactions/developer/{developerId}` | Interactions by developer |
| GET | `/api/developer-interactions/security-event/{securityEventId}` | Interactions on an event |
| GET | `/api/behaviour-logs`, `/{id}`, `/developer/{developerId}` | Read behaviour logs (same table as interactions) |
| POST | `/api/behaviour-logs` | **Deprecated.** Same logic as interactions; responds with `Deprecation: true` and a `Link` header |
| GET | `/api/lifecycle-history/security-event/{securityEventId}` | Status history of an event |
| GET | `/api/lifecycle-history/security-event/{securityEventId}/verify` | Check that the event's history was not altered (`VALID`, `BROKEN`, `UNCHAINED`) |
| GET | `/api/developer-behaviour/{developerId}` | Behaviour summary and classification |
| GET | `/api/developer-behaviour/{developerId}/response-sequences` | Behaviour Sequence Intelligence: recurring response sequences, patterns and transitions (descriptive) |

**Errors** go through one `GlobalExceptionHandler` and return an `ApiErrorResponse`:

| Status | Meaning |
|---|---|
| `400` | Validation failed, or the GitHub token is missing |
| `401` | GitHub rejected the token |
| `403` | The developer does not own the event |
| `404` | Resource not found |
| `409` | Duplicate resource, invalid lifecycle transition, or GitHub account conflict |
| `502` | The GitHub API is unavailable |
| `500` | Unexpected server error |

**Dashboard** ([`frontend/`](component-2-behaviour-tracker/frontend/)). A React web app
for exploring the tracker's data. In development, Vite proxies `/api` to
`http://localhost:8080`. Pages:

| Route | Page |
|---|---|
| `/` | Home, a list of developers |
| `/developers/:developerId` | Developer profile |
| `/developers/:developerId/security-events` | Security events |
| `/developers/:developerId/lifecycle` | Lifecycle timeline |
| `/developers/:developerId/behaviour` | Behaviour analysis |
| `/quality` | Quality & Regression Tests: results of the latest backend test run (local dev server only) |

The app supports light and dark themes.

**Tests.** 432 test methods in 34 classes: API contracts for every endpoint (including the
exact requests C1 sends), GitHub sign-in with GitHub's HTTP mocked, ownership, all 25 lifecycle
status × action pairs, claimed versus verified fixes, hash-chain tampering, rollback on failed writes, concurrent actions and
`schema.sql` against the entities. They run against H2 in memory, so no PostgreSQL is needed.
`npm run test:report` in `frontend/` summarises the last run; see
[`backend/README.md`](component-2-behaviour-tracker/backend/README.md#tests-and-test-reports).

**Tech stack.**
- **Backend:** Java 17 · Spring Boot 3.3.5 (Web, Data JPA, Validation) · Hibernate ·
  PostgreSQL 14+ via HikariCP · springdoc-openapi 2.6.0 · Lombok · Maven · JUnit 5,
  Spring Boot Test and H2 2.1 for tests.
- **Dashboard:** React 19 · React Router 7 · Axios · TypeScript 5.9 · Vite 6.

Full backend detail is in [`component-2-behaviour-tracker/backend/README.md`](component-2-behaviour-tracker/backend/README.md).

---

### C3 · Intelligent Feedback Engine

**Owner:** D R Pathirage (IT23202122) · **Folder:** `component-3-feedback-engine/` ·
**Branch:** `Component-3` (initial setup on `main`) · **Port:** 8083

**Problem.** Static tools give every developer the same warning at the same strength. A
developer who has ignored the same SQL injection warning four times sees exactly what a
first-timer sees.

**Objective.** Receive security alerts and behaviour history, analyse each issue's type and
severity, strengthen the warning when the same mistake keeps happening, and return
personalised secure-coding recommendations in a clear form.

**Novelty.** Feedback adapts to repeated behaviour and risk level. For example, a first SQL
injection may get a MEDIUM warning with a suggested fix. The same issue ignored again and
again escalates to a stronger level with a firmer explanation and remediation guidance.

**Severity scoring**
([`SeverityScoringService`](https://github.com/Ruwaneke/J26-IT-394/blob/Component-3/component-3-feedback-engine/src/main/java/com/sentinel/feedback/scoring/SeverityScoringService.java)):

```
score = base(severity) + confidence adjustment + min(5 × earlier findings of the same type, 15)
score is clamped to 0–100, then banded
```

| Base severity | Base score | | Confidence | Adjustment | | Score | Level |
|---|---|---|---|---|---|---|---|
| INFO | 0 | | < 0.5 | −10 | | 0–19 | INFO |
| LOW | 20 | | 0.5–0.89 | 0 | | 20–39 | LOW |
| MEDIUM | 40 | | ≥ 0.9 | +10 | | 40–59 | MEDIUM |
| HIGH | 65 | | | | | 60–79 | HIGH |
| CRITICAL | 85 | | | | | 80–100 | CRITICAL |

A confidence outside 0.0–1.0 is rejected.

**Behaviour-aware escalation**
([`FeedbackEscalationService`](https://github.com/Ruwaneke/J26-IT-394/blob/Component-3/component-3-feedback-engine/src/main/java/com/sentinel/feedback/scoring/FeedbackEscalationService.java)):

- **2 or more earlier ignores:** the level goes up one step.
- **Otherwise, 3 or more earlier fixes:** the level goes down one step.
- Ignores are checked first. The level never goes below `INFO` or above `CRITICAL`.

**Recommendation templates**
([`RecommendationTemplateService`](https://github.com/Ruwaneke/J26-IT-394/blob/Component-3/component-3-feedback-engine/src/main/java/com/sentinel/feedback/recommendation/RecommendationTemplateService.java)).
Each vulnerability type has a title, guidance and a secure example:

| Type | Recommendation | Secure example |
|---|---|---|
| `SQL_INJECTION` | Use parameterised database queries | `connection.prepareStatement("SELECT * FROM users WHERE id = ?")` |
| `XSS` | Escape untrusted output | `element.textContent = untrustedValue;` |
| `HARDCODED_SECRET` | Move secrets to secure configuration | `System.getenv("API_KEY")` |
| `COMMAND_INJECTION` | Avoid shell interpretation of user input | `new ProcessBuilder("git", "status")` |
| `PATH_TRAVERSAL` | Constrain file access to an allowed directory | `baseDirectory.resolve(input).normalize()` |
| `MISSING_INPUT_VALIDATION` | Validate input at the trust boundary | `@Valid @RequestBody CreateRequest request` |
| `UNSAFE_DESERIALIZATION` | Deserialise only trusted, constrained data | `new ObjectMapper()` with a type allowlist |
| `WEAK_CRYPTOGRAPHY` | Use modern approved cryptography | `MessageDigest.getInstance("SHA-256")` |
| `INSECURE_AUTH` | Enforce strong authentication controls | `new BCryptPasswordEncoder()` |
| `SENSITIVE_DATA_EXPOSURE` | Minimise and protect sensitive data | Return a summary DTO instead of the entity |

**Models** (Java records with Bean Validation):

| Record | Fields |
|---|---|
| `SecurityEvent` | `eventId`, `developerId`, `sessionId`, `vulnerabilityType`, `severity`, `confidence` (0.0–1.0), `fileName`, `lineNumber`, `detectedAt` |
| `BehaviourHistory` | `developerId`, `previousFindings`, `previousFixes`, `previousIgnores`, `findingsByType` |
| `FeedbackResponse` | `eventId`, `score`, `severity`, `message` |

**Development plan** (milestone: at least 50% of C3 by 20 October 2026). The engine is
developed standalone on mock C1 and C2 data:

| Date | Planned work | Status |
|---|---|---|
| 12 Oct | Spring Boot setup and project structure | Done |
| 13 Oct | `SecurityEvent`, `BehaviourHistory`, `FeedbackResponse` models | Done |
| 14 Oct | Severity-scoring rules | Done |
| 15 Oct | Feedback escalation engine | Done |
| 16 Oct | Secure-coding recommendation templates | Done |
| 17 Oct | Personalised recommendation generator | Planned |
| 18 Oct | Main feedback engine integration | Planned |
| 19 Oct | REST API development and testing | Planned |
| 20 Oct | Unit testing, bug fixing, milestone demonstration | Planned |

**Tests.** 10 test methods: the context load, severity scoring at each level and boundary,
escalation in both directions and at both bounds, and template coverage.

**Tech stack.** Java 21 · Spring Boot 3.3.5 (Web, Validation) · Maven · JUnit 5 with Spring
Boot Test.

---

### C4 · Analytics and Dashboard

**Owner:** D S Gayanatha (IT23233058) · **Folder:** `component-4-dashboard/` ·
**Branch:** `feature/analytics` · **Runs in:** VS Code webview (dev preview on port 5173)

**Problem.** Dashboards show how many vulnerabilities exist. They do not show whether
developers are improving, who is likely to struggle next, or which behaviours go together.
That is the evidence this research needs.

**Objective.** Measure developer improvement over time, classify developers into risk
profiles, run correlation analysis across behaviours, forecast future behaviour from
historical trends, and generate an automated research summary report, all shown in a
dashboard.

**Novelty.** One place shows security issues together with behaviour trends, forecasts and
improvement, with every statistical claim tied to a stated test and its result.

> **Simulated data.** C1–C3 do not yet produce enough real data, so every result in C4 comes
> from a seeded simulator built on stated assumptions. The numbers describe those
> assumptions, not real developers. Real events will replace the simulated ones through the
> same event schema.

**Pipeline** (`python -m src.pipeline` runs every step in order; each step can also run on
its own):

| Step | Module | What it does |
|---|---|---|
| 1 | `simulate.py` | Generates 60 developers over 16 weeks (seed 42) in four archetypes: 30% improving, 30% stagnant, 20% worsening, 20% erratic. Each archetype has its own trajectories for detection rate, fix propensity, ignore share, response time and repeat propensity; erratic developers follow a mean-reverting AR(1) walk. Writes `events.jsonl`, `sessions.jsonl` and `developers.csv` (ground truth, never a model input). |
| 2 | `features.py` | One row per developer per week, with these features: `vuln_count`, fix, ignore and false-positive rates, `avg_response_time`, `repeat_count` (same type + file in the previous 4 weeks), severity-weighted load (LOW 1, MEDIUM 2, HIGH 3), ignored-severity load, HIGH count, per-type counts, sessions and intro rate per session. |
| 3 | `trends.py` | 4-week moving averages, week-over-week change, rolling 4-week OLS slope; per-developer direction (improving / stable / worsening at a ±0.02 per week threshold); team series with pooled rates. |
| 4 | `forecast.py` | A 1-layer **GRU or LSTM** (PyTorch) that predicts `vuln_count` and `fix_rate` for the next 2 weeks from the last 3–4 weeks of 7 inputs. Masked Huber loss, AdamW (lr 0.003), gradient clipping, early stopping. Grid search over hidden size, window and dropout on the validation weeks only; 5 seeds; a chronological train/validation/test split. Compared with naive, 4-week-mean and linear-trend baselines using MAE, RMSE, sMAPE and paired Wilcoxon tests. A NumPy GRU is tested against PyTorch. |
| 5 | `risk.py` | A **research risk profile** (LOW / MEDIUM / HIGH) for the next 4 weeks from behaviour up to the current week. The label is `0.4 × severity-weighted ignore rate + 0.3 × (1 − fix rate) + 0.2 × repeat rate + 0.1 × log response time`, banded with frozen thresholds. Models: **XGBoost** and multinomial logistic regression, compared with majority-class, static fix-rate-rule and persistence baselines. Evaluated with repeated `GroupKFold` (5 × 5) by developer, developer-level bootstrap CIs and paired bootstrap tests. SHAP gives global importance. The reasons shown per developer are their own measured metrics against the study median. |
| 6 | `correlation.py` | Pearson and Spearman correlations with Fisher-z CIs across 7 behaviour variables. Developer-level analysis (n = 60) is the main one; developer-week analysis is secondary. Benjamini-Hochberg correction across the 21 pairs. |
| 7 | `recommend.py` | Rules defined as data in `config.yaml` (R1–R8 plus the fallback R0), each with a priority and plain-language template. Conditions are structured `{field, op, value}` data and are never evaluated as code. Up to 3 recommendations per developer. |
| 8 | `export.py` | Writes `analytics.json` and validates it against `analytics.schema.json` (JSON Schema 2020-12). Also refreshes the committed 20-developer sample the frontend uses. |
| 9 | `report.py` | Writes `research_summary.md` and `research_summary.html`, with greyscale 200 dpi figures. Every comparison sentence is generated from the significance verdicts, and a test checks that no tie is reported as a win. |

**Results on simulated data (seed 42).**

| Question | Result |
|---|---|
| Forecasting | The deployed GRU (MAE 3.76 findings per week, 0.250 fix-rate MAE) beats the naive and linear baselines but **ties the 4-week mean**. |
| Risk classification | XGBoost macro F1 0.521 [0.463, 0.567]. It beats logistic regression, the fix-rate rule and the majority class, but **ties persistence**. |
| Overall | Recent behaviour is the strongest predictor on this data. |
| Correlations | 10 of 21 developer-level pairs are significant after Benjamini-Hochberg correction. Two of them are partly true by construction. |

Post-hoc changes (the residual forecast mode and the extended risk features) are labelled as
post-hoc wherever they appear.

**Dashboard.** A React app (Recharts), bundled into its own VS Code extension, **Sentinel
Analytics** (`Sentinel Analytics: Open Dashboard`, or the status-bar item).
- **Tabs:** Overview, Trends, Forecast, Risk, Correlations, Recommendations, Model
  evaluation. Every tab shows a "Simulated data" banner.
- **Data source:** loads the bundled sample by default, or the file set in
  `sentinelAnalytics.dataPath`.
- **Security:** the webview runs under a strict CSP (`default-src 'none'`, nonce-only
  scripts), loads assets only from the extension's `media/` folder, and makes no network
  calls.
- **Types:** TypeScript types are generated from the JSON schema and checked in tests.

**Tests.** Python: 10 test modules (pytest), one per pipeline step plus the GRU check.
Frontend: Vitest validates the sample against the schema and checks the generated types.

**Tech stack.**
- **ML pipeline:** Python 3.12 · NumPy 2.5 · pandas 3.0 · SciPy 1.18 · PyTorch 2.14 (CPU) ·
  scikit-learn 1.9 · XGBoost 3.4 · SHAP 0.53 · jsonschema 4.26 · Matplotlib 3.11 · PyYAML ·
  pytest 9.
- **Frontend:** React 19 · Recharts 3 · TypeScript 7 · Vite 8 · Vitest 5 · Ajv ·
  json-schema-to-typescript.
- **Extension:** VS Code API (^1.90.0) · esbuild · `@vscode/vsce`.

Full detail is in `component-4-dashboard/README.md` and `component-4-dashboard/ml/README.md`
on the `feature/analytics` branch.

## 6. Shared interface contracts

| Contract | From | To | Defined in |
|---|---|---|---|
| `SecurityFinding` | C1 internal | C1 → C2 mapping | [`sentinel/src/analyzer/types.ts`](sentinel/src/analyzer/types.ts) |
| Security event (`POST /api/security-events`) | C1 | C2 | `CreateSecurityEventRequest` in C2 |
| Developer interaction (`POST /api/developer-interactions`) | C1 | C2 | `CreateDeveloperInteractionRequest` in C2 |
| GitHub sign-in (`POST /api/auth/github`) | C1 | C2 | `GitHubAuthRequest` in C2 |
| `SecurityEvent` + `BehaviourHistory` → `FeedbackResponse` | C2 / C1 | C3 | C3 `model/` package |
| C4 event record (`events.jsonl`) | C2 (planned) | C4 | `component-4-dashboard/ml/README.md` |
| `analytics.json` | C4 pipeline | C4 dashboard | `component-4-dashboard/ml/analytics.schema.json` |

**The C1 → C2 contract is frozen.** Changes go into C2, not into the extension's calls.

The full integration guide is in
[docs/architecture/INTEGRATION.md](docs/architecture/INTEGRATION.md). It covers every
interface, mismatch, mapping, open decision and the roadmap.

### `SecurityFinding` (C1)

```typescript
interface SecurityFinding {
  id: string;                 // unique per finding instance
  type: VulnerabilityType;    // SQL_INJECTION | XSS | HARDCODED_SECRET | COMMAND_INJECTION |
                              // PATH_TRAVERSAL | MISSING_INPUT_VALIDATION | UNSAFE_DESERIALIZATION |
                              // WEAK_CRYPTOGRAPHY | INSECURE_AUTH | SENSITIVE_DATA_EXPOSURE
  severity: Severity;         // CRITICAL | HIGH | MEDIUM | LOW | INFO
  confidence: number;         // 0.0–1.0
  message: string;
  fileName: string;
  lineNumber: number;         // 1-indexed
  columnNumber: number;       // 0-indexed
  codeSnippet: string;
  detectedAt: string;         // ISO 8601
  detectedByRule: string;
  rangeStart?: number;
  rangeEnd?: number;
}
```

### C1 → C2 requests

```jsonc
// POST /api/security-events
{ "developerId": 1, "vulnerabilityType": "SQL_INJECTION", "severity": "HIGH",
  "fileName": "UserDao.java", "lineNumber": 42, "message": "Unsanitised input in query",
  "detectedAt": "2026-10-17T10:15:00" }          // optional; alias "timestamp"; defaults to now

// POST /api/developer-interactions
{ "securityEventId": 1, "developerId": 1, "action": "FIX",
  "sessionId": "…", "source": "VSCODE",
  "metadata": "{\"extensionAction\":\"FIX_APPLIED\",\"confidence\":0.92}",
  "actionTimestamp": "2026-10-17T10:16:30" }     // optional; defaults to now
```

C1's `INFO` severity is sent to C2 as `LOW`, because C2 has no `INFO` level.

### How a click in the editor becomes a lifecycle change

| C1 `DeveloperAction` | Sent to C2 as | C2 status |
|---|---|---|
| `DETECTED` | `POST /api/security-events` | `DETECTED` |
| `WARNING_SHOWN` | not sent | — |
| `EXPLANATION_VIEWED`, `SECURE_EXAMPLE_VIEWED` | `OPEN` | `OPENED` |
| `FIX_APPLIED`, `FIXED` | `FIX` | `FIXED` (a claimed fix, `fixVerification: CLAIMED`) |
| `IGNORED`, `MARKED_FALSE_POSITIVE` | `IGNORE` | `IGNORED` |
| `DISMISSED` | `DISMISS` | `IGNORED` |
| `REOPEN` | `REOPEN` | `REOPENED` |

### C4 event record

```jsonc
{ "eventId": "uuid", "developerId": "…", "sessionId": "…",
  "vulnerabilityType": "SQL_INJECTION", "severity": "HIGH", "confidence": 0.91,
  "fileName": "…", "lineNumber": 120, "detectedAt": "ISO 8601",
  "action": "FIXED | IGNORED | DISMISSED | FALSE_POSITIVE",
  "fixedAt": "ISO 8601 or null", "responseTime": 312.4 }
```

An ingest adapter that maps C2's tables onto this record is planned. `sessions.jsonl` is an
optional input proposed to C2 and is not yet part of the contract.

## 7. Data, privacy and ethics

| Store | Holds | Written by |
|---|---|---|
| PostgreSQL `developer_behavior` | Developers (GitHub id, login, email), security events, behaviour logs, lifecycle history | C2 only |
| Local JSON in `sentinel/src/data/` | Per-developer vulnerability records and learning profiles; users, projects, shifts | C1 (to be replaced by Neon PostgreSQL on `hishen_dev`) |
| `component-4-dashboard/ml/data`, `outputs/` | Simulated events and generated analytics (not committed) | C4 |

- **Code samples** come from public repositories, benchmark datasets and research papers.
  The deliberately vulnerable `test_project/` was written by the team.
- **Behaviour data** comes from controlled testing by the team. C4 uses simulated data
  only, and labels every output with `dataSource: "simulated"`.
- **Identity.** C2 trusts only identity that GitHub has verified at sign-in. Other
  endpoints currently accept the `developerId` the client sends; the ownership check stops
  a developer acting on another developer's events through that id.
- **Credentials.** Database credentials come from environment variables. The real
  `application.properties` is git-ignored and only a placeholder template is committed.
  Local passwords are stored as SHA-256 hashes, not plain text.
- **Risk profiles describe measured behaviour, not people.** C4's risk bands and reasons
  are framed as a research profile of recent behaviour, not a judgement of the person.
- **Human participants.** Collecting behaviour data from real developers, identifying them,
  or recording individual coding habits counts as human-participant research. Before any
  such study, the team will seek university ethical clearance and:
  - obtain informed consent;
  - anonymise data where possible;
  - store data securely;
  - use it only for academic research.

## 8. Technology stack

| Layer | Technology |
|---|---|
| C1 extension | TypeScript 5.4, VS Code Extension API ^1.85, node-fetch 3, ESLint, vsce; `pg` + Neon PostgreSQL (`hishen_dev`) |
| C2 backend | Java 17, Spring Boot 3.3.5 (Web, Data JPA, Validation), Hibernate, PostgreSQL 14+, HikariCP, springdoc-openapi 2.6.0, Lombok, Maven |
| C2 dashboard | React 19, React Router 7, Axios, TypeScript 5.9, Vite 6 |
| C3 engine | Java 21, Spring Boot 3.3.5 (Web, Validation), Maven |
| C4 ML pipeline | Python 3.12, NumPy, pandas, SciPy, PyTorch (GRU/LSTM), scikit-learn, XGBoost, SHAP, Matplotlib, jsonschema, PyYAML |
| C4 dashboard | React 19, Recharts 3, TypeScript 7, Vite 8, esbuild, VS Code webview |
| Testing | JUnit 5, Spring Boot Test, H2 (C2, C3) · pytest (C4 ML) · Vitest, Ajv (C4 frontend) |
| Authentication | GitHub OAuth (VS Code auth provider) verified server-side against the GitHub REST API |
| Tooling | Git and GitHub, VS Code launch and tasks configs, Swagger UI |

## 9. Repository layout and branches

```
J26-IT-394/
├── sentinel/                         C1 · VS Code extension
│   └── src/
│       ├── extension.ts              entry point: wiring, commands, debounce, webview messages
│       ├── analyzer/                 SecurityAnalyzer + shared types (SecurityFinding)
│       ├── rules/                    SQL injection, XSS, hardcoded-secret rules
│       ├── ai/                       AI-enhanced analyser, per-developer learning store
│       ├── diagnostics/              Problems panel, hover, code actions, contextual explainer
│       ├── events/                   SecurityEventClient → C2
│       ├── auth/                     GitHub OAuth + password fallback, roles
│       ├── webview/                  login, developer, supervisor, admin dashboards
│       ├── data/                     local JSON stores (records, learning, users, projects, shifts)
│       └── util/
├── component-2-behaviour-tracker/    C2
│   ├── backend/                      Spring Boot API (controller, service, repository, entity, dto,
│   │                                 enums, exception, client, config) + tests
│   ├── frontend/                     React dashboard
│   └── database/                     migration, schema, sample-data areas
├── component-3-feedback-engine/      C3 · Spring Boot (model, scoring, recommendation)
├── component-4-dashboard/            C4
│   ├── ml/                           Python pipeline, config.yaml, analytics.schema.json, tests
│   ├── frontend/                     React dashboard
│   └── extension/                    VS Code extension that hosts the dashboard
├── database/ · deployment/ · docs/ · shared/ · testing/
│                                     shared areas (placeholders for now)
└── .vscode/                          launch and compile tasks for the Sentinel extension
```

Each component is developed on its own branch and merged into `main` through pull
requests:

| Branch | Contents |
|---|---|
| `main` | Integration branch: C1, the initial C3 setup, and placeholder folders |
| `dev` | Shared development branch: an earlier snapshot of C2 |
| `feature/component-2-backend-foundation` | C2 backend, dashboard and C1 ↔ C2 integration (latest C2) |
| `Component-3` | C3 feedback engine |
| `feature/analytics` | C4 ML pipeline, dashboard and its extension |
| `hishen_dev` | C1 work: OWASP Top 10 rules, Neon PostgreSQL, test project |
| `supundev` | `dev` merged with the C3 scoring work |

## 10. Getting started

### Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| VS Code | 1.85+ (C1), 1.90+ (C4 extension) | C1, C4 dashboard |
| Node.js | 20+ | C1, C2 dashboard, C4 frontend and extension |
| JDK | 17+ for C2, 21 for C3 | C2, C3 |
| Maven | 3.9+ | C2, C3 |
| PostgreSQL | 14+ | C2 |
| Python | 3.12 | C4 ML pipeline |

### End-to-end (C1 + C2)

```bash
# 1. Database
createdb developer_behavior

# 2. C2 backend → http://localhost:8080
cd component-2-behaviour-tracker/backend
cp src/main/resources/application.properties.example src/main/resources/application.properties
export DB_USERNAME=<your-db-user> DB_PASSWORD=<your-db-password>
mvn spring-boot:run

# 3. C2 dashboard → http://localhost:5173
cd ../frontend && npm install && npm run dev

# 4. C1 extension
cd ../../sentinel && npm install && npm run compile
```

Open the repository in VS Code and press **F5** (**🛡 Launch Sentinel Extension**). In the
Extension Development Host window:
1. Sign in with GitHub from the Sentinel login view.
2. Paste a vulnerable line into any file, for example
   `string query = "SELECT * FROM Users WHERE id=" + userId;`.
3. Use **Explain**, **Fix** or **Ignore**.
4. Check the result in the C2 dashboard, or with
   `curl localhost:8080/api/developer-behaviour/1`.

### One component

**C2 tests** (no database needed):

```bash
cd component-2-behaviour-tracker/backend && mvn test
```

**C3** (on the `Component-3` branch), served at http://localhost:8083:

```bash
cd component-3-feedback-engine
mvn test
mvn spring-boot:run
```

**C4** (on the `feature/analytics` branch). On Windows use `py -3.12` and
`.venv/Scripts/python`.

```bash
cd component-4-dashboard/ml
python3.12 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m src.pipeline --quick      # under 1 minute; drop --quick for the full run (~5 min)
.venv/bin/python -m pytest

cd ../frontend && npm install
cd ../extension && npm install && npm run build
```

Then open `component-4-dashboard/extension` in VS Code, press **F5**, and run **Sentinel
Analytics: Open Dashboard**.

### Ports

| Service | Port |
|---|---|
| C2 Behaviour Tracker API (Swagger UI at `/swagger-ui.html`) | 8080 |
| C3 Feedback Engine | 8083 |
| C2 dashboard (Vite dev) | 5173 |
| C4 dashboard browser preview (Vite dev) | 5173 (run one at a time, or Vite will pick the next free port) |
| PostgreSQL | 5432 |
| C1 and the C4 extension | run inside VS Code; no port |

## 11. Project status

IT4010, 2026. Detection, tracking, feedback scoring and analytics each work on their own.
The full integration path is the remaining work.

| Component | State |
|---|---|
| C1 | Working: real-time SQLi, XSS and secrets detection (57 patterns); editor diagnostics and code actions; GitHub sign-in; role-based dashboards; event reporting to C2. OWASP Top 10 rules and Neon storage in progress on `hishen_dev`. |
| C2 | Working: full REST API, enforced lifecycle, behaviour analysis and classification, GitHub verification, tamper-evident lifecycle history, claimed versus verified fixes, behaviour sequence intelligence, dashboard, 432 tests with a test report page. Connected to C1. |
| C3 | Scoring, escalation and templates done with tests. Recommendation generator, engine integration and REST API scheduled for 17–20 October 2026. |
| C4 | Full pipeline, dashboard and report working on simulated data. The ingest adapter for real C2 data is planned. |

**Known integration gaps**

- C1's `sentinel.ifeUrl` defaults to `http://localhost:4000` and calls
  `/api/feedback/request`. C3 runs on port 8083 and does not expose a REST API yet.
- C4 reads simulated events. Mapping C2 data into the C4 event schema is not built yet.
- C3's `BehaviourHistory` (earlier findings, fixes and ignores) is not yet filled from C2's
  behaviour summary.
- C1 sends `FIX` when the developer uses the Fix action, without re-checking the code. C2
  stores every fix as `CLAIMED`; verified fixes need C1 to report whether the finding is
  still present after a fix.

## 12. Team

| Component | Member | Student ID |
|---|---|---|
| C1 · Real-time code detection (Sentinel VS Code extension) | M H S Perera | IT23163218 |
| C2 · Developer behaviour tracking | R S D Sulakshana | IT23249752 |
| C3 · Intelligent feedback engine | D R Pathirage | IT23202122 |
| C4 · Analytics and web dashboard | D S Gayanatha | IT23233058 |

Supervisor and co-supervisor: *to be added*.

This repository is an academic research project for the J26-IT-394 team.

## 13. References

1. Offline, Multi-Language Code Vulnerability Detection Plugin Using Graph Neural Networks
   and LLM-Guided Explanations.
2. N. P. Nguyen et al., "Structure-Aware Code Vulnerability Analysis With Graph Neural
   Networks," arXiv, 2023.
3. "Detecting Code Vulnerabilities with Heterogeneous Graph Neural Networks," arXiv, 2025.
4. F. Fagerholm, A. Sanchez Guinea, J. Mäenpää and J. Münch, "Patterns of Developers'
   Behaviour: A 1000-Hour Industrial Study," *Journal of Systems and Software*, 2017.
5. T. Chen et al., "A Study on Developer Behaviors for Validating and Repairing
   LLM-Generated Code Using Eye Tracking and IDE Actions," 2024.
6. M. B. Kery et al., "Characterizing Developer Behavior in Cloud-Based IDEs," IEEE/ACM
   ESEM, 2017.
7. M. Hazhirpasand et al., "Towards Immediate Feedback for Security Relevant Code in
   Development Environments," arXiv, 2022.
