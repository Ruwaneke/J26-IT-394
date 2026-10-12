# Component 3: Intelligent Feedback Engine Development Plan

**Milestone deadline:** October 20, 2026  
**Target:** Demonstrate at least 50% of the standalone Intelligent Feedback Engine.

## Scope and working rules

- Build a standalone prototype using mock Component 1 security-event data and mock Component 2 behaviour-history data.
- Keep implementation changes inside `component-3-feedback-engine` unless approval is given.
- Test each feature before marking its daily task complete.
- Commit verified progress to the `Component-3` branch daily. Ask for confirmation before every commit and push.
- Prioritize severity scoring, escalation, personalized recommendations and the REST API over optional features.
- Do not begin full system integration until the standalone engine is working.

## Daily schedule

| Date | Planned work | Completion evidence |
|---|---|---|
| October 12 | Spring Boot setup and project structure | Application starts and the context test passes |
| October 13 | `SecurityEvent`, `BehaviourHistory` and `FeedbackResponse` models | Model tests cover the mock input and response shapes |
| October 14 | Severity-scoring rules and implementation | Scoring tests cover each severity level and boundary |
| October 15 | Feedback escalation engine | Escalation tests verify severity and behaviour-history rules |
| October 16 | Secure-coding recommendation templates | Template tests verify the core vulnerability categories |
| October 17 | Personalized recommendation generator | Generator tests verify recommendations use event and behaviour data |
| October 18 | Main feedback engine integration | Integration tests produce complete feedback from mock inputs |
| October 19 | REST API development and testing | API tests verify request validation and response status/payload |
| October 20 | Unit testing, bug fixing and milestone demonstration | Full Component 3 test suite passes and the milestone demo is ready |

The daily task is complete only after its stated evidence is verified.
