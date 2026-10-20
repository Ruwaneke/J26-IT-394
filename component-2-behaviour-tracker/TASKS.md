# Component 2 · Developer Behaviour Tracker — Tasks

The ordered work plan for Component 2. Whoever does the work, it is picked from here, done
as described here, and ticked off here. The aim is that the work never drifts from the plan
halfway through.

Read [COMPONENT_OVERVIEW.md](COMPONENT_OVERVIEW.md) for *why* and
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) for *how*. The technical overview's
non-negotiable rules (§0) and definition of done (§17) apply to every task below.

**Owner:** R S D Sulakshana (IT23249752) · **Last reviewed:** 20 October 2026

---

## How to use this file

1. **Work top to bottom.** Phases are in priority order. Inside a phase, take the first
   unticked task whose dependencies are done.
2. **One task at a time.** Finish it, meaning it meets the definition of done, before
   starting the next. Do not mix two tasks in one commit.
3. **Follow the steps as written.** If a step turns out wrong, first change the task here
   (and say why in the progress log), then do the work.
4. **Respect the gates.**
   - 🔐 needs agreement from another component's owner or the supervisor before coding.
   - 📝 is a proposal only: write it up, do not implement.
5. **Tick the box and add the date** in the same commit as the work, for example
   `- [x] Done 2026-10-18`.
6. **Log anything unexpected** in the progress log at the bottom.
7. **Do not add work silently.** New ideas go to the backlog (Phase 6) until the owner
   moves them up.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done · `[-]` dropped (with
a reason).

---

## Snapshot (17 October 2026)

| TAF task | State |
|---|---|
| T1 Receive security events from C1 | ✅ Done |
| T2 Store type, file, line, time, response | ✅ Done |
| T3 Track ignored / fixed / **repeated** | 🟡 Repeated is only a count per vulnerability type |
| T4 Group repeated mistakes by **type and session** | 🟡 Not grouped by session; no repeat link |
| T5 Behaviour summaries | ✅ Done |

**Uncommitted work on the branch:**
- the untracked `generate-test-data.sh`;
- changes to C1's `sentinel/src/data/*.json`. **These are not C2 files; do not commit them
  with C2 work.**

**Fixed 2026-10-20:** a second `OPEN` on the same finding no longer gets `409` (P1-1).

---

## Phase 0 · Housekeeping

### P0-1 · Commit the lazy-loading fix for behaviour-log reads
- [x] Done 2026-10-20

**Why.** With `open-in-view=false`, mapping a log's developer or event outside a loaded
graph throws `LazyInitializationException` (a `500`). The fix is written but not committed.

**Do**
1. Review the diff of `backend/.../repository/BehaviourLogRepository.java`. It adds
   `@EntityGraph(attributePaths = {"developer", "securityEvent"})` to `findById`,
   `findByDeveloperId`, `findBySecurityEventId` and `findByDeveloperIdAndActionType`.
2. Review `BehaviourLogServiceImpl.java`. The method-level `@Transactional(readOnly = true)`
   repeats the class-level one, which is harmless. Keep it or remove it, but be consistent.
3. Add a `@DataJpaTest` that saves a developer, an event and a log, then calls each
   repository method and maps the result to `BehaviourLogResponse` and
   `DeveloperInteractionResponse` without error.
4. Run `mvn test`.
5. Stage **only** the two C2 files and the new test.

**Done when.** Tests pass. The commit contains no `sentinel/` files.
**Depends on.** —

### P0-2 · Review and commit the synthetic test-data script
- [ ] Status

**Why.** A repeatable synthetic dataset is needed for demos, for checking metrics, and
later for evaluation (P4-1).

**Do**
1. Read `generate-test-data.sh` end to end.
2. Make sure every action sequence it sends follows the lifecycle in TECHNICAL_OVERVIEW §4.3.
   Until P1-1 is done, it must not send same-status actions, or expect `409` where it does.
3. Make sure the developers it creates are clearly synthetic (for example identifiers
   starting with `synthetic-`), so they can never be mistaken for real participants.
4. Make sure it is idempotent: running it twice must not fail on existing developers.
5. Run it against a fresh database. Check the counts it prints against
   `GET /api/developer-behaviour/{id}`.
6. Add a "Synthetic test data" section to `backend/README.md` describing usage.

**Done when.** The script runs cleanly twice in a row on a fresh database, and is
documented.
**Depends on.** P0-1.

### P0-3 · Commit the documentation set
- [ ] Status

**Do.** Commit the root `README.md`, the root `CLAUDE.md`, and this component's
`COMPONENT_OVERVIEW.md`, `TECHNICAL_OVERVIEW.md` and `TASKS.md`, with no Claude or AI
mention in the message.
**Done when.** They are on the branch and pushed after the owner confirms.
**Depends on.** —

---

## Phase 1 · Correctness

### P1-1 · Accept same-status actions without a lifecycle entry
- [x] Done 2026-10-20

**Why.** C1 sends `OPEN` both when an explanation is viewed and when a secure example is
viewed. The second one has the same target status, gets `409`, and is dropped silently by
C1 after 3 retries. `DISMISS` after `IGNORE` has the same problem. `backend/README.md`
already documents the intended behaviour: "logged but adds no history entry".

**Do**
1. In `DeveloperInteractionServiceImpl.createInteraction`, after the ownership check:
   - if `targetStatus == currentStatus`:
     - save the `BehaviourLog` as usual, including the response time;
     - do **not** change the status;
     - do **not** write a history row;
     - return `201`;
   - otherwise keep the existing transition check (`409` for disallowed transitions).
2. Keep the pessimistic lock and keep the ownership check first.
3. Update the Javadoc of the method and the class.
4. Add tests:
   - service: second `OPEN` → log saved, status unchanged, `lifecycleHistoryRepository.save`
     never called;
   - service: `DISMISS` on `IGNORED` → same;
   - controller: second `OPEN` → `201`;
   - controller: `OPEN` on `FIXED` → still `409`.
5. Check `BehaviourAnalysisServiceImpl` still counts distinct events. Repeated `OPEN` logs
   must not change any rate (add a test).
6. Update TECHNICAL_OVERVIEW §4.4 to "current behaviour". In the root `README.md`, remove
   the two related bullets from "Known integration gaps" and drop "including a repeat of the
   current status" from the C2 write-path description. In `backend/README.md`, check the
   lifecycle section still matches.

**Done when.** All four tests pass. Repeating a click in the extension no longer loses
data. The docs agree with the code.
**Depends on.** P0-1.

### P1-2 · Bring backend/README.md in line with the code
- [ ] Status

**Do**
1. Error handling section: add `401` (GitHub token rejected), `403` (not the event's owner)
   and `502` (GitHub unavailable) next to 400, 404, 409 and 500.
2. Lifecycle endpoint: list the alias paths (`/api/lifecycle/...`, `/{id}` forms) that the
   dashboard uses.
3. Interactions: document the ownership rule (`403`) and the response-time calculation.
4. Mention that `detectedAt` also accepts `timestamp`, and that `lineNumber` 0 is accepted.
5. Point to `COMPONENT_OVERVIEW.md`, `TECHNICAL_OVERVIEW.md` and `TASKS.md` at the top.

**Done when.** Every endpoint, status code and rule in the README can be found in the
code, and the reverse.
**Depends on.** P1-1.

### P1-3 · Close the test gaps
- [x] Done 2026-10-20 (as part of P1-5)

**Do**
1. `DeveloperInteractionServiceImpl` unit tests (Mockito):
   - history row written with the correct from, to, `changedAt` and `changedBy`;
   - `findByIdForUpdate` is the method used;
   - `timeSinceDetectionSeconds` is correct, both with and without `actionTimestamp`;
   - `403` happens before the transition check;
   - `404` for a missing developer or event.
2. `SecurityEventStatusTest`: a table-driven test of all 25 from → to pairs against
   TECHNICAL_OVERVIEW §4.3.
3. `VulnerabilityLifecycleHistoryService`: results come back oldest first; `404` for an
   unknown event.
4. `LifecycleHistoryController`: all four paths return `200`.

**Done when.** The new tests pass and the test count in TECHNICAL_OVERVIEW §13.1 is
updated.
**Depends on.** P1-1.

### P1-4 · End-to-end check with the real extension
- [ ] Status

**Do**
1. Run PostgreSQL and the backend. Launch the extension with F5 from the repo root. Sign in
   with GitHub.
2. Run this sequence on one finding and record the results:
   - detect;
   - view the explanation (`OPEN`);
   - view the secure example (`OPEN` again; expect `201` after P1-1);
   - Ignore;
   - re-detection or reopen if available;
   - Fix.
3. Check with the API:
   - one event;
   - the expected interaction count;
   - history = only the real transitions;
   - the summary updated.
4. Save the steps and results as `docs/e2e-check.md` (create `component-2-behaviour-tracker/docs/`).
   Screenshots are optional.

**Done when.** Every action sent by C1 is stored, and the record is committed.
**Depends on.** P1-1.

### P1-5 · API contract and regression test suite, with a test report page
- [x] Done 2026-10-20

**Why.** The frozen C1 → C2 contract, the lifecycle rules and the P2-9 hash chain are only
partly covered by tests, and `POST /api/auth/github` and `/api/developers` have no API-level
tests at all. The owner asked (20 October 2026) for a contract and regression suite, and for
the results to be visible in the dashboard. This task also does P1-3's steps (marked below).

**Do**
1. Contract tests on the real stack (`@SpringBootTest` + H2) for every endpoint in
   TECHNICAL_OVERVIEW §8.1: success shapes, the C1 request bodies exactly as C1 sends them,
   missing, blank, malformed and out-of-range values, invalid enums, invalid JSON, ISO-8601
   timestamps, status codes and the `ApiErrorResponse` format. Assert current behaviour; do
   not change any API to make a test pass.
2. GitHub sign-in through the real controller with GitHub's HTTP mocked
   (`MockRestServiceServer`; no real token): `400`, `401`, `502` (5xx, rate limit, network
   failure, incomplete profile), new, returning and legacy developers, the `409` conflict,
   client-supplied identity fields ignored, the token never echoed or logged.
3. Ownership: `403` before `409`, and nothing stored on `403` or `404`.
4. Lifecycle: all 25 status × action pairs on the real stack (transition, same-status or
   `409`), with the history row's from, to, `changedAt` and `changedBy`, and nothing stored on
   `409`. A table-driven `SecurityEventStatus` test of all 25 status pairs (P1-3 step 2).
5. Hash chain (P2-9): unit tests of the verification policy, and H2 cases not yet covered
   (altered hash values, missing `DETECTED` entry, an entry moved to another event, separate
   chains per event, client timestamps out of order, a legacy event with no history). The
   policy is unchanged: no history is `BROKEN`, legacy rows are `UNCHAINED`.
6. Database consistency: a failing history write rolls back the event or the action;
   concurrent actions on one event keep the status, history and chain consistent; repository
   queries; `schema.sql` matches the entity mappings and can be re-run.
7. P1-3 step 1 and 3: `DeveloperInteractionServiceImpl` rules (Mockito) and
   `VulnerabilityLifecycleHistoryService` (oldest first, `404`).
8. A machine-readable report from Surefire's XML (`npm run test:report`), and a **Quality &
   Regression Tests** page in the dashboard that shows it. Running the suite from the page is
   only possible on the local Vite dev server: one fixed command (`mvn -B test`), no
   arguments from the browser, one run at a time, a timeout, and no database credentials
   passed on. No backend endpoint runs tests.
9. Docs: TECHNICAL_OVERVIEW §11 and §13, `backend/README.md`, COMPONENT_OVERVIEW §9.

**Done when.** `mvn test` passes with the new tests, `npm run build` and `npm test` pass, and
the page shows the results of a real run.
**Depends on.** P1-1, P2-9.

### P1-6 · Tell claimed fixes apart from verified fixes
- [x] Done 2026-10-20

**Why.** C1 sends `FIX` when the developer uses the Fix code action, which only shows the
secure example (`sentinel/src/extension.ts`, `handleFixAction`). C2 moved the event to
`FIXED` and counted it in `fixRate` as if the code had been fixed. Found by a review of the
lifecycle state machine requested by the owner (20 October 2026).

**Do**
1. Add `FixVerificationStatus` (`CLAIMED`, `VERIFIED`, `STILL_VULNERABLE`) and a nullable
   `behaviour_logs.fix_verification` (entity, `schema.sql` `CREATE TABLE` and `ALTER TABLE`,
   and a re-runnable update that marks older `FIX` rows `CLAIMED`).
2. Add `FixVerificationService`, with `ClaimOnlyFixVerificationService` returning `CLAIMED`
   until a verification source exists. Call it from `createInteraction` for `FIX` only; a
   `null` answer is `CLAIMED`.
3. Keep the lifecycle and the C1 contract unchanged: `FIX` still moves to `FIXED` with `201`,
   also when the result is `STILL_VULNERABLE`.
4. Add `fixVerification` to `DeveloperInteractionResponse`, and `verifiedFixCount` and
   `verifiedFixRate` to the behaviour summary (additive). Keep `fixRate` and the
   classification unchanged (a change needs the supervisor, TECHNICAL_OVERVIEW §7.3).
5. Tests with controlled mock verification results: service rules (Mockito), the real stack
   with C1's bodies (`@SpyBean`), analysis, schema re-run.
6. Docs: TECHNICAL_OVERVIEW §3.2, §4.5, §5.2, §7.1, §13.1, §16; `backend/README.md`;
   COMPONENT_OVERVIEW; root `README.md`; frontend `types.ts`.
7. 📝 Ask C1's owner to report whether a finding is still present after a fix (see "Notify
   other components"). Do not edit `sentinel/`.

**Done when.** Every `FIX` stores a verification value, nothing reports `VERIFIED` without a
source, the C1 contract and lifecycle are unchanged, and the tests pass.
**Depends on.** P1-1.

---

## Phase 2 · Complete TAF tasks T3 and T4 (repeated mistakes and sessions)

This is the core research work still left for C2. New analysis code goes in the `analysis/`
package (TECHNICAL_OVERVIEW §1.2). P2-9 (tamper-evident history) is outside T3 and T4. It is
a research addition from the Component 2 Enhancement Guide, and needs only P1-1.

### P2-1 · Decide the definition of a "repeated mistake" 🔐 supervisor
- [ ] Status

**Why.** "Repeated" is currently "a vulnerability type appearing more than once". That is
too coarse: with only a few types, almost everything counts as a repeat. C4 found the same
problem with a type-only definition, where 86% of detections counted as repeats.

**Do**
1. Write a short decision note in `docs/decisions/001-repeated-mistake.md`. **Recommended
   definition**, aligned with C4 so both components measure the same thing:
   - a security event is a **repeat** if the same developer had an earlier event with the
     **same `vulnerability_type` and the same `file_name`**;
   - optionally, only count it within a look-back window (C4 uses 4 weeks).
2. Decide:
   - whether the earlier event must have been `FIXED` or `IGNORED` first (the mistake *came
     back*), or just have existed;
   - whether a look-back window applies, and how long;
   - whether the same line counts as the same mistake or a duplicate detection.
3. Get the supervisor's agreement. Record the date and decision in the note and the
   progress log.

**Done when.** The note is committed with an agreed definition.
**Depends on.** —

### P2-2 · Link each repeat to its earlier event
- [ ] Status

**Do**
1. Add a nullable `repeat_of_event_id BIGINT REFERENCES security_events(id) ON DELETE SET
   NULL` to `security_events`:
   - in the entity (`@ManyToOne(fetch = LAZY)`, `@Index`);
   - in `schema.sql`, both `CREATE TABLE` and `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
2. In `SecurityEventServiceImpl.createSecurityEvent`, inside the same transaction, find the
   most recent earlier event matching the P2-1 definition and set `repeat_of_event_id`.
   Add the repository query with an index-friendly filter: developer, type, file,
   `detected_at < :detectedAt`.
3. Add `repeatOfEventId` (nullable) to `SecurityEventResponse`. This is an additive response
   field, so it is safe for C1.
4. Add a backfill SQL to `schema.sql` (commented, run once) or a documented one-off script,
   to link existing rows.
5. Tests:
   - first occurrence → null;
   - second occurrence → linked to the first;
   - third → linked to the second;
   - different file or type → null;
   - outside the window → null (if a window applies).
6. Update the frontend `types.ts`, TECHNICAL_OVERVIEW §3.2 and `backend/README.md`.

**Done when.** New events are linked automatically, existing data is backfilled, and the
tests pass.
**Depends on.** P2-1.

### P2-3 · Give security events a session
- [ ] Status

**Why.** T4 asks for grouping by session, but sessions exist only on interactions.

**Do**
1. Add a nullable `session_id VARCHAR(255)` to `security_events` (entity, index,
   `schema.sql`).
2. Add an **optional** `sessionId` (≤ 255) to `CreateSecurityEventRequest`. Optional and
   additive keeps C1 compatible.
3. Until C1 sends it: when the first interaction on an event arrives and the event's
   `session_id` is null, copy the interaction's `sessionId` onto the event, in the same
   transaction.
4. Backfill existing events from their earliest interaction's `session_id`.
5. 📝 Write a short proposal for C1's owner (M H S Perera) asking to send `sessionId` with
   detections. Record it under "Notify other components" below. **Do not edit `sentinel/`.**
6. Tests:
   - a provided `sessionId` is stored;
   - a missing one is filled by the first interaction;
   - a later interaction does not overwrite it.

**Done when.** Every event that has had an action has a session. Tests pass. The proposal
is sent.
**Depends on.** P1-1.

### P2-4 · Repeated-mistakes endpoint
- [ ] Status

**Do**
1. Add `GET /api/developer-behaviour/{developerId}/repeated-mistakes`, with the logic in
   `analysis/RepeatedMistakeAnalysis` (or similar) and a service method.
2. Response (agree the field names before building the frontend):
   - `byType`: per vulnerability type: total events, repeat events, repeat rate, first seen,
     last seen;
   - `byTypeAndFile`: per (type, file): occurrences, chain of event ids, statuses, last seen;
   - `bySession`: per session: events, repeats within the session, repeats of earlier
     sessions.
3. `404` for an unknown developer. Empty lists for a developer with no events.
4. Tests with a hand-built dataset that covers all three groupings.
5. Document it in `backend/README.md` and TECHNICAL_OVERVIEW §8.1.

**Done when.** The endpoint returns correct groupings for the test dataset.
**Depends on.** P2-2, P2-3.

### P2-5 · Session summary endpoint
- [ ] Status

**Do**
1. Add `GET /api/developer-behaviour/{developerId}/sessions`. Per session:
   - `sessionId`;
   - start and end (earliest and latest event or action time);
   - detections;
   - actions by type;
   - fixes, ignores and repeats;
   - average response time.
2. Sort by start time, oldest first.
3. Tests and docs as in P2-4.

**Done when.** Sessions are listed correctly for the test dataset.
**Depends on.** P2-3.

### P2-6 · Add repeat metrics to the behaviour summary
- [ ] Status

**Do**
1. Add these fields to `DeveloperBehaviourSummaryResponse` (additive):
   - `repeatEventCount`;
   - `repeatRate` (repeat events / total events, %);
   - `sessionCount`.
2. Keep `repeatedVulnerabilityCount` unchanged. Other consumers may use it.
3. 🔐 If the classification should use `repeatRate` instead of `repeatedVulnerabilityCount ≥
   3`, agree it with the supervisor first. Then change §7.2 rules, tests and `Badges.tsx`
   `CLASSIFICATION_RULES` together (TECHNICAL_OVERVIEW §7.3).
4. Tests, including edge values.

**Done when.** The summary includes the new fields with correct values. Any classification
change is agreed and applied everywhere.
**Depends on.** P2-2, P2-3.

### P2-7 · Weekly improvement series
- [ ] Status

**Why.** The research question is about improvement *over time*. C2 should provide the raw
weekly aggregates. Forecasting stays in C4.

**Do**
1. Add `GET /api/developer-behaviour/{developerId}/trend?from=&to=`. Per ISO week:
   - detections;
   - distinct fixed, ignored and reopened events;
   - fix and ignore rates;
   - repeat events;
   - average response time.
2. Weeks with no activity are returned with zeros and `null` rates, not left out.
3. No modelling or forecasting here (that is C4's scope).
4. Tests and docs.

**Done when.** The weekly series is correct for the test dataset, including empty weeks.
**Depends on.** P2-2.

### P2-8 · Dashboard: repeated mistakes, sessions, trend
- [ ] Status

**Do**
1. Add `api` calls and types for P2-4, P2-5 and P2-7.
2. On the behaviour analysis page, add a repeated-mistakes section (by type, then by type
   and file).
3. Add a sessions view (list, then session detail).
4. Add a weekly trend chart. Pick a charting approach consistent with the dashboard; C4
   uses Recharts.
5. Handle loading, error and empty states with the shared components. Show repeat and
   session data from the summary (P2-6).
6. Run `npm run build`.

**Done when.** All three views work against the synthetic dataset and the build passes.
**Depends on.** P2-4, P2-5, P2-6, P2-7.

### P2-9 · Tamper-evident lifecycle history (hash chain)
- [x] Done 2026-10-20

**Why.** Anyone with database access can edit a history row (for example `IGNORED` →
`FIXED`) and the timeline still looks normal. For behaviour data used as research evidence,
C2 must be able to show when history was altered. This is Upgrade 1 of the Component 2
Enhancement Guide (18 October 2026). It is internal to C2: no C1, C3 or C4 change.

**Do**
1. Add `prev_hash` and `entry_hash` (`VARCHAR(64)`, nullable) to
   `vulnerability_lifecycle_history`:
   - in `VulnerabilityLifecycleHistory`;
   - in `schema.sql`, both `CREATE TABLE` and `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
2. Add a small hasher in `analysis/` (or `util/`), for example `LifecycleHashChain`:
   - `entryHash = SHA-256(prevHash | securityEventId | previousStatus | newStatus |
     changedAt | changedBy)`, hex-encoded, with a fixed field separator and `null` written
     as an empty string;
   - the first entry of each event uses a fixed genesis value as `prevHash`;
   - truncate `changedAt` to microseconds before it is saved and hashed. PostgreSQL rounds
     finer values, so truncating only for the hash is not enough.
3. Set both hashes wherever a history row is written, inside the existing transaction:
   - `SecurityEventServiceImpl.createSecurityEvent` (the `DETECTED` row, genesis
     `prevHash`);
   - `DeveloperInteractionServiceImpl.createInteraction` (transitions). `prevHash` is the
     `entryHash` of the event's latest row, read while the existing pessimistic lock is held,
     so two concurrent actions cannot fork the chain.
   Same-status actions (P1-1) still write no history row and so do not touch the chain.
4. Add `GET /api/lifecycle-history/security-event/{securityEventId}/verify`:
   - recomputes the chain, oldest first;
   - walks the rows in id (insertion) order, not `changed_at` order, because `changed_at`
     comes from the client and need not increase;
   - returns `status` (`VALID`, `BROKEN`, or `UNCHAINED` for rows written before this task),
     `entryCount`, `unchainedEntryCount`, `brokenAtEntry`, `brokenAtHistoryId` and `reason`
     (null unless `BROKEN`), and `verifiedAt`;
   - `404` for an unknown event.
   Rows written before this task have null hashes. Report them as `UNCHAINED`; do not
   backfill them, because that would vouch for history that was never protected.
5. Add `entryHash` to `LifecycleHistoryResponse` (additive).
6. Tests:
   - hasher: same input gives same hash; changing any field changes it; microsecond
     truncation;
   - service: the first row uses the genesis value; each later row's `prevHash` equals the
     previous `entryHash`;
   - verify, as an integration test on H2, one case per tampering type: an edited status
     in a middle entry, an edited timestamp, a deleted middle entry, two reordered entries,
     and no tampering. Each must give `BROKEN` at the expected entry, or `VALID`;
   - legacy rows with null hashes → `UNCHAINED`;
   - record the extra write time per history row (ms) for the evaluation (P4-3).
7. Document it:
   - TECHNICAL_OVERVIEW §3.2 (columns), §5.1 and §5.2 (write paths), §8.1 (endpoint),
     §13.1 (test count);
   - `backend/README.md`;
   - the frontend `types.ts` if the dashboard shows it;
   - state the limit in COMPONENT_OVERVIEW: the history is tamper-*evident*, not
     tamper-proof. Someone with full database access who knows the algorithm can rebuild
     the chain, and deleting the newest entries is not detected without an outside anchor.
8. 📝 Optional follow-up: write up an outside anchor (storing each chain's latest hash
   outside the database) as a proposal in `docs/proposals/`. Do not build it in this task.

**Done when.** Every new history row is chained. The verify endpoint detects all four
tampering cases at the right entry and returns `VALID` for untouched history. Tests pass,
and the docs state the tamper-evident limit.
**Depends on.** P1-1. It does not depend on P2-1 to P2-8 and can be taken before them.

---

## Phase 3 · Integration with C3 and C4

### P3-1 · Agree the behaviour-history contract with C3 🔐 D R Pathirage
- [ ] Status

**Do**
1. Propose the mapping from TECHNICAL_OVERVIEW §10.1 to C3's `BehaviourHistory`
   (`developerId`, `previousFindings`, `previousFixes`, `previousIgnores`,
   `findingsByType`).
2. Settle these points:
   - "previous" = before a given event, or all time;
   - ignores include dismissals or not;
   - the `developerId` type (C3 uses a string);
   - whether C3 calls C2, or C2's data is passed in by someone else.
3. Record the agreed contract as a JSON example in `docs/contracts/c3-behaviour-history.md`.

**Done when.** C3's owner confirms in writing (PR comment or message). Record it in the log.
**Depends on.** —

### P3-2 · Behaviour-history endpoint for C3
- [ ] Status

**Do.** Implement the agreed endpoint, for example
`GET /api/developer-behaviour/{developerId}/history?vulnerabilityType=&beforeEventId=`,
exactly as in `docs/contracts/c3-behaviour-history.md`. Count distinct events, as in the
summary. Add tests with hand-calculated values and docs.
**Done when.** C3's owner can call it and gets the agreed shape.
**Depends on.** P3-1.

### P3-3 · Read confidence and the original action from metadata
- [ ] Status

**Why.** C4 needs `confidence` and a `FALSE_POSITIVE` action. Both exist only inside
`context_metadata` (`{"extensionAction": "...", "confidence": 0.92}`).

**Do**
1. Add a small parser in `analysis/` that reads `extensionAction` and `confidence` from
   `context_metadata`.
2. It must return empty values, not throw, when the field is null, is not JSON, lacks the
   keys, or has the wrong types.
3. Use Jackson (already on the classpath).
4. Tests for every one of those cases.
5. Do **not** change the stored metadata or the C1 request.

**Done when.** The parser is tested against valid and malformed inputs.
**Depends on.** —

### P3-4 · Agree the export contract with C4 🔐 D S Gayanatha
- [ ] Status

**Do.** Using TECHNICAL_OVERVIEW §10.2, agree:
- one record per event with the **first** response, or with the **final** one;
- how `IGNORE` versus `DISMISS` versus false positive map onto C4's
  `IGNORED`/`DISMISSED`/`FALSE_POSITIVE`;
- how `CRITICAL` maps, since C4 has LOW/MEDIUM/HIGH;
- what to do with events that have no response yet;
- pseudonymised developer ids;
- whether to also export `sessions`;
- the format (NDJSON matching `events.jsonl`).

Record the decisions in `docs/contracts/c4-event-export.md`.
**Done when.** C4's owner confirms. Record it in the log.
**Depends on.** P2-3, P3-3.

### P3-5 · Event export endpoint for C4
- [ ] Status

**Do**
1. Implement the agreed export, for example `GET /api/export/c4/events?from=&to=` and
   `GET /api/export/c4/sessions` as `application/x-ndjson`.
2. Stream the results; do not load everything into memory.
3. Validate the output against a sample from C4 (field names, types, enum values) in a test.
4. Apply the agreed pseudonymisation.

**Done when.** C4's pipeline can read the file in place of `data/raw/events.jsonl`, as
confirmed by C4's owner.
**Depends on.** P3-4.

---

## Phase 4 · Research data and evaluation

### P4-1 · Extend synthetic data for repeats and sessions
- [ ] Status

**Do.** Extend `generate-test-data.sh` (or replace it with a seeded generator) so the data
includes:
- several sessions per developer;
- the same mistake (type + file) returning across sessions;
- some developers improving and some not.

Keep everything labelled synthetic.
**Done when.** The P2 endpoints show non-trivial repeats, sessions and trends on this data.
**Depends on.** P0-2, P2-2, P2-3.

### P4-2 · Agree evaluation criteria 🔐 supervisor
- [ ] Status

**Do.** Take the proposed criteria in COMPONENT_OVERVIEW §11 to the supervisor. Record the
agreed criteria and any numeric targets in COMPONENT_OVERVIEW §11, replacing "proposed".
**Done when.** The criteria are agreed and written down.
**Depends on.** —

### P4-3 · Produce the evaluation evidence
- [ ] Status

**Do.** For each agreed criterion:
- write a repeatable check, either a test or a script under `docs/evaluation/`;
- record the result with the date and commit hash.

Include at least:
- completeness: N actions sent, N stored;
- lifecycle correctness;
- metric correctness on a fixture;
- repeat and session grouping correctness.

**Done when.** Every criterion has a recorded, reproducible result.
**Depends on.** P4-2, P1-4, Phase 2.

### P4-4 · Ethics readiness for real participants 🔐 supervisor
- [ ] Status

**Do.** Before any study with real developers:
- confirm ethical clearance;
- prepare the consent text;
- make sure exports are pseudonymised (P3-5);
- document data retention and deletion (deleting a developer cascades to their events);
- document who can access the database.

**Done when.** Clearance is confirmed and the procedures are written in `docs/ethics.md`.
**Depends on.** P3-5.

---

## Phase 5 · Hardening

### P5-1 · 📝 Proposal: bind requests to a verified identity
- [ ] Status

**Why.** `developerId` in the body is asserted by the client (TECHNICAL_OVERVIEW §9.3).
**Do.** Write `docs/proposals/auth-binding.md`. It should cover:
- issuing a C2 token at `POST /api/auth/github`;
- C1 sending it as a header;
- C2 deriving the developer from it;
- a migration plan that keeps the old behaviour working until C1 switches.

Share it with C1's owner. **Do not implement** without agreement, because it changes the
frozen contract.
**Done when.** The proposal is written and shared.
**Depends on.** —

### P5-2 · Pagination for list endpoints
- [ ] Status

**Do.** Add optional `page` and `size` parameters to the GET-all endpoints that C1 does not
use. With no parameters, the current behaviour must stay unchanged so the dashboard does not
break. Update the dashboard where lists can grow.
**Depends on.** —

### P5-3 · Remove N+1 queries in `findAll` reads
- [ ] Status

**Do.** Add `@EntityGraph` overrides (or fetch-join queries) for `findAll` where the
results are mapped through lazy relations. Verify with SQL logging on test data.
**Depends on.** P0-1.

### P5-4 · CI for Component 2
- [ ] Status

**Do.** Add a GitHub Actions workflow, triggered only on changes under
`component-2-behaviour-tracker/**`, that runs `mvn test` (JDK 17) and `npm ci && npm run
build` for the frontend. Agree it with the team first, since `.github/` is shared.
**Depends on.** —

### P5-5 · Local PostgreSQL with Docker Compose
- [ ] Status

**Do.** Add `component-2-behaviour-tracker/docker-compose.yml` with PostgreSQL 16 and
credentials taken from `.env` (git-ignored), plus a README section.
**Depends on.** —

### P5-6 · Versioned migrations (Flyway) 🔐 team
- [ ] Status

**Do.** Replace `ddl-auto=update` and `schema.sql` with Flyway migrations (`V1__baseline.sql`
from the current schema, then one file per change). Set `ddl-auto=validate`. Test it on a
copy of an existing database.
**Depends on.** All Phase 2 schema changes done (to avoid migrating twice).

---

## Phase 6 · Backlog (do not start without the owner moving it up)

- Remove the deprecated `POST /api/behaviour-logs` once it is confirmed that nothing calls
  it (C1 does not).
- Restrict `POST /api/developers` (open create endpoint) to test or admin use.
- Classification thresholds from data rather than design, once real data exists.
- Developer comparison or team views in the dashboard (check overlap with C4 first).
- Export the dashboard's views as a PDF report.
- Map Spring MVC's own errors to their 4xx codes in `GlobalExceptionHandler`: a non-numeric
  path id, an unknown route, a wrong `Content-Type` and a wrong method now return `500`
  (found by P1-5). Changes status codes clients see, so agree it first. Also: a concurrent
  duplicate developer gets `500` instead of `409`; `400` messages for unreadable bodies can
  show Java type names; timestamps ending in `Z` lose their zone while `+05:30` is rejected.

---

## Do not do

- Edit anything under `sentinel/`, `component-3-feedback-engine/` or
  `component-4-dashboard/`.
- Change paths, required fields or success codes of `POST /api/auth/github`,
  `POST /api/security-events` or `POST /api/developer-interactions`.
- Write `behaviour_logs` rows or change `current_status` anywhere except
  `DeveloperInteractionService`.
- Add forecasting, ML models or severity scoring to C2. Those belong to C4 and C3.
- Let the dashboard create or modify events or interactions.
- Commit `application.properties`, `.env`, `target/`, `dist/`, `node_modules/`, or C1's
  `sentinel/src/data/*.json`.
- Mention Claude or AI in commit messages or PRs, or add an AI co-author trailer.
- Commit or push without the owner's confirmation.

---

## Notify other components

Issues found while working on C2 that belong to someone else. Tell the owner; do not fix
their code.

| To | Issue | Status |
|---|---|---|
| C1 · M H S Perera | Please send `sessionId` with detections (`POST /api/security-events`, optional field; C2 accepts it after P2-3) | Not sent |
| C1 · M H S Perera | `sentinel.ifeUrl` defaults to `http://localhost:4000` (`/api/feedback/request`), but C3 runs on 8083 with no REST API yet | Not sent |
| C1 · M H S Perera | Two different actions (explanation viewed, example viewed) both map to `OPEN`; C2 will accept repeats after P1-1, but the distinction only survives in metadata | For info |
| C4 · D S Gayanatha | C2 and C4 dashboards both use Vite port 5173 | For info |
| C1 · M H S Perera | 📝 `FIX` is sent when the Fix action shows the secure example, not after the code changed. Please report whether the finding is still present after a fix (for example a re-scan result for the event), so C2 can mark fixes `VERIFIED` or `STILL_VULNERABLE` (P1-6) | Not sent |
| C1 · M H S Perera | `sentinel/README.md` shows `POST /api/auth/github` with `githubId`/`githubUsername`/`email`; C1's code and C2 use `{"githubAccessToken"}` | For info |

---

## Progress log

Newest first. One line per notable event: task done, decision made, plan changed, problem
found.

| Date | Entry |
|---|---|
| 2026-10-20 | P1-6 done (added the same day at the owner's request, after a review of the lifecycle state machine): every `FIX` stores `fixVerification` (`CLAIMED` unless a verification source says otherwise); `ClaimOnlyFixVerificationService` is the only source, so every fix is `CLAIMED`; tests use controlled mock results. Lifecycle, C1 contract, `fixRate` and classification unchanged; `verifiedFixCount`/`verifiedFixRate` added. 20 new test methods in 2 new classes and 2 existing ones (382 → 402, all pass); with the stored value removed, 10 of the 17 new write-path tests fail. Review result for the other points: transitions, `409`, the `DETECTED` entry, history fields, transactions and tests were already in place. Exact duplicate deliveries (a C1 retry after a timeout) are stored as a second log because no request id exists; a dedup key would need C1 to send one. |
| 2026-10-20 | Plan changed: added P1-6 (claimed versus verified fixes), requested by the owner. |
| 2026-10-20 | P1-5 done (added the same day at the owner's request; P1-3's steps are part of it and P1-3 is ticked): 254 new test methods in 14 classes (128 → 382, all pass, `mvn test` about 8 s of Maven time). Contract tests run on the real stack with C1's exact bodies; GitHub is mocked with `MockRestServiceServer`. Checked that the new tests fail when the lifecycle, the row lock or `schema.sql` are broken. Dashboard: `/quality` page reading Surefire's XML through a dev-server-only Vite plugin (fixed `mvn test`, no input, no credentials passed, one run at a time, 10 min limit); `npm run test:report` writes `backend/target/quality-report.json`; `npm test` (Node's built-in runner, 10 tests) covers the report reader and the runner's guards. No API, lifecycle, schema or hash-chain policy was changed. Found and left as is (backlog): several Spring MVC errors give `500` instead of 4xx; see TECHNICAL_OVERVIEW §13.1. |
| 2026-10-20 | Plan changed: added P1-5 (API contract and regression test suite, with a test report page), requested by the owner. |
| 2026-10-20 | P2-9 done: lifecycle history is hash-chained (`analysis/LifecycleHashChain`), and `GET /api/lifecycle-history/security-event/{id}/verify` reports `VALID`/`BROKEN`/`UNCHAINED`. Tamper tests on H2: edited status, edited timestamp, deleted, reordered, re-hashed and hash-stripped rows are all `BROKEN` at the expected entry; untouched history is `VALID`; deleting the newest row is not detected (documented limit, outside anchor still 📝). Cost on H2, in-process: about 0.17 ms extra per history write (latest-row read + hash); verifying 205 rows took about 5 ms (one run, indicative only; measure on PostgreSQL for P4-3). Changes to the task as written: the chain follows id order, `changed_at` is truncated before saving (not only before hashing), `detected_at` is truncated too, and the response adds `unchainedEntryCount` and `reason`. 128 tests pass; frontend build passes. |
| 2026-10-20 | Plan changed: added P2-9, a tamper-evident lifecycle history (Upgrade 1 of the Component 2 Enhancement Guide). The guide's other upgrades are not in the plan yet. U2, U3 and U6 need C1 changes. U4 and U5 touch C4's scope (COMPONENT_OVERVIEW §6). |
| 2026-10-20 | P1-1 done: same-status actions are logged with `201`, no status change, no history row. Controller test step done as `DeveloperInteractionFlowIntegrationTest` (real stack on H2) instead of a mocked-service MockMvc test, which could not detect the change. Note: repeated logs still count towards `averageResponseTimeSeconds` and the `INSUFFICIENT_DATA` action count (TECHNICAL_OVERVIEW §4.4). 105 tests pass. |
| 2026-10-20 | P0-1 done: the `@EntityGraph` fix was already committed in `70aeb8e`; added `BehaviourLogRepositoryTest` (fails if a graph is removed). |
| 2026-10-17 | System integration guide written at `docs/architecture/INTEGRATION.md`. P3-1/P3-2 (I3) and P3-3..P3-5 (I4) follow its §7–§8 and open decisions D1, D3–D8. |
| 2026-10-17 | Plan created. T1, T2 and T5 done; T3 and T4 partial. Open issue: same-status actions get 409 (P1-1). |
