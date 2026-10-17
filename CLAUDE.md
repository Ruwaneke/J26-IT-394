# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Read first

[README.md](README.md) is the source of truth for what this project is, what each component
does, the contracts between components, ports, and how to run everything. Follow it. If the
code and the README disagree, say so instead of silently picking one, and keep the README in
step with any change that affects it.

## Before any change to the repo

Before **any** change to this repository, whether a code change, a config or doc change, or
a commit, read these four files and follow them. Do this every time, not only for
Component 2 work:

1. [component-2-behaviour-tracker/TASKS.md](component-2-behaviour-tracker/TASKS.md):
   - Take work only from here, in order.
   - Tick the task and update the progress log in the same commit.
   - Don't start backlog, 🔐-gated or 📝 proposal-only tasks without approval.
   - If a change isn't covered by a task, say so and ask before doing it.
2. [component-2-behaviour-tracker/COMPONENT_OVERVIEW.md](component-2-behaviour-tracker/COMPONENT_OVERVIEW.md):
   the component's purpose and scope. Stay inside them.
3. [component-2-behaviour-tracker/TECHNICAL_OVERVIEW.md](component-2-behaviour-tracker/TECHNICAL_OVERVIEW.md):
   - Its §0 non-negotiable rules and §17 definition of done are mandatory.
   - Use its §14 recipes for common changes.
4. [sentinel/README.md](sentinel/README.md): Component 1, the VS Code extension. It is the
   client of Component 2. Check every change against how the extension calls the backend,
   so the frozen C1 → C2 contract is never broken.

If a change makes any of these files out of date, update the file in the same change.

## Project in one paragraph

Sentinel (J26-IT-394, IT4010 research project) is a four-component system: **C1** the
Sentinel VS Code extension in `sentinel/` detects vulnerabilities as code is typed; **C2**
the Developer Behaviour Tracker in `component-2-behaviour-tracker/` (Spring Boot + PostgreSQL
backend, React dashboard) records each warning's lifecycle and the developer's response;
**C3** the Intelligent Feedback Engine in `component-3-feedback-engine/` scores and escalates
feedback; **C4** the analytics pipeline and dashboard in `component-4-dashboard/`.

## Rules

### Commits and pull requests

- **Never add Claude as a co-author.** No `Co-Authored-By: Claude …` trailer.
- **Never mention Claude, Claude Code or AI generation** in commit messages, PR titles or
  PR descriptions. No "Generated with Claude Code" lines.
- Commit or push only when asked. Ask for confirmation before every commit and push.
- Never commit to `main` directly. Work on the component's branch and merge through a pull
  request.
- Commit only verified work: the relevant tests pass first.

### Scope and ownership

- Keep changes inside the component you are working on. Do not edit another component's
  folder unless the user asks.

  | Component | Folder | Branch | Owner |
  |---|---|---|---|
  | C1 | `sentinel/` | `hishen_dev` | M H S Perera |
  | C2 | `component-2-behaviour-tracker/` | `feature/component-2-backend-foundation` | R S D Sulakshana |
  | C3 | `component-3-feedback-engine/` | `Component-3` | D R Pathirage |
  | C4 | `component-4-dashboard/` | `feature/analytics` | D S Gayanatha |

- **The C1 → C2 contract is frozen.** Do not change the paths, request/response shapes or
  success status codes of `POST /api/auth/github`, `POST /api/security-events` and
  `POST /api/developer-interactions`. Change C2 to fit C1, not the other way round. If a
  change would need C1 to change, propose it; do not implement it.
- Changing a shared contract (`SecurityFinding`, the C2 request DTOs, C3's models, C4's
  event record or `analytics.schema.json`) needs the owning member's agreement.

### Security and data

- Never commit credentials. `component-2-behaviour-tracker/backend/src/main/resources/application.properties`
  is git-ignored; only `application.properties.example` with placeholders is committed.
  Credentials come from environment variables (`DB_USERNAME`, `DB_PASSWORD`, …).
- Never commit `.env`, `node_modules/`, `dist/`, `target/`, or C4's generated
  `ml/data/` and `ml/outputs/`.
- C4 results are simulated. Never present them as real developer data.
- Treat developer behaviour data as research data about people: no new personal fields
  without a reason, and nothing that identifies a developer outside the system.

### Working style

- Test each change before calling it done, and report test results as they are.
- Match the surrounding code: naming, comment density, package layout.
- C2 actions go through `DeveloperInteractionService` (the single write path). Status
  changes must respect `SecurityEventStatus.allowedTransitions()`, and every status change
  writes a lifecycle history entry.

## Commands

| Task | Command |
|---|---|
| C1 build | `cd sentinel && npm install && npm run compile` (then F5 in VS Code) |
| C1 lint | `cd sentinel && npm run lint` |
| C2 backend run | `cd component-2-behaviour-tracker/backend && mvn spring-boot:run` (port 8080, needs PostgreSQL) |
| C2 backend tests | `cd component-2-behaviour-tracker/backend && mvn test` (H2, no database needed) |
| C2 dashboard | `cd component-2-behaviour-tracker/frontend && npm install && npm run dev` (port 5173) |
| C3 tests / run | `cd component-3-feedback-engine && mvn test` / `mvn spring-boot:run` (port 8083) |
| C4 pipeline | `cd component-4-dashboard/ml && .venv/bin/python -m src.pipeline --quick` |
| C4 tests | `cd component-4-dashboard/ml && .venv/bin/python -m pytest`; `cd component-4-dashboard/frontend && npm test` |
