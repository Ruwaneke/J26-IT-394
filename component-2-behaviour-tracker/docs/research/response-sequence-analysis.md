# Behaviour Sequence Intelligence — method note

Component 2 · TASKS **P2-10** · 21 October 2026

This note records how Component 2 turns stored developer actions into response sequences,
patterns and transition shares, and what the results can and cannot support. The
implementation is
[`analysis/ResponseSequenceAnalysis.java`](../../backend/src/main/java/com/sentinel/tracker/analysis/ResponseSequenceAnalysis.java);
the engineering summary is TECHNICAL_OVERVIEW §7.4.

## 1. Research question

> Can developer security-response sequence analysis reveal recurring behavioural patterns
> that aggregate action counts alone cannot adequately represent?

This feature provides the measurement. It does not answer the question by itself: that
needs real participant data and an evaluation agreed with the supervisor (TASKS P4-2, P4-3).
No claim of better prediction or better developer performance is made.

## 2. Data used

| Record | Used? | Why |
|---|---|---|
| `behaviour_logs` | **Yes, only source** | One row per developer action accepted by C2: `OPEN`, `FIX`, `IGNORE`, `DISMISS`, `REOPEN`, with the developer, the security event and the action time. |
| `vulnerability_lifecycle_history` | No | The first entry (`null → DETECTED`) is written by `SYSTEM` when C1 reports a detection; it is not a developer action. Every later entry copies a logged action that changed the status, so reading it would count those actions twice. |
| `security_events` | Ownership only | Restricts sequences to the developer's own events. |

Actions rejected by the lifecycle (`409`) or by the ownership check (`403`) are never stored,
so every logged action already respects the state machine.

**Not recorded, so not analysed** (documented, not invented):
- *Warning shown* and *detected*: C1 does not send them as actions.
- Which C1 action produced a C2 action (`EXPLANATION_VIEWED` versus `SECURE_EXAMPLE_VIEWED`
  both arrive as `OPEN`; `MARKED_FALSE_POSITIVE` arrives as `IGNORE`). The original name exists
  only in the free-text `context_metadata`, which is not parsed yet (TASKS P3-3).
- Whether a `FIX` changed the code. Every `FIX` is a *claimed* fix (TASKS P1-6).
- A request id. A C1 retry after a 5 s timeout can store the same click twice.

## 3. Sequence extraction

For one developer:

1. Read their behaviour logs. A log id seen twice counts once.
2. Exclude logs with no security event (the event was deleted) or on an event the developer
   does not own (`excludedActionRecords`).
3. Group the remaining logs by security event. Logs on different events never join.
4. If any log of an event has no timestamp, exclude the whole event
   (`excludedIncompleteEvents`): its order is unknown. (The column is NOT NULL, so this
   protects against legacy or malformed rows only.)
5. Order each event's logs by action timestamp (`timestamp`, the time C1 reports), ties by log
   id (insertion order). Client timestamps need not match insertion order; the action time
   is used because it is when the developer acted.
6. Merge consecutive identical actions into one step (`collapsedRepeatActions`). C1 sends
   `OPEN` for both the explanation and the secure example, and a retried request repeats an
   action; neither is a new response step. Non-consecutive repeats stay
   (`OPEN, IGNORE, OPEN`).

Each remaining event gives one **complete response sequence**. Their number is
`totalEligibleSequences`, the denominator of every support percentage.

## 4. Measures

**Frequent patterns.** Every contiguous window of 2 to 5 steps in every sequence.
- *Occurrence count:* all windows equal to the pattern, including repeats inside one sequence.
- *Sequence count:* sequences containing the pattern at least once.
- *Support* = sequence count ÷ `totalEligibleSequences` × 100, one decimal.
- *Most recent occurrence:* the action time of the last step of the latest window.
- Reported only if the sequence count ≥ `min-pattern-sequences` (default 2) **and** support ≥
  `min-support-percent` (default 10%). Sub-patterns of a frequent pattern are also listed
  (no closed-pattern pruning).

**Transitions.** Every consecutive step pair within a sequence.
- *Probability* = count(A → B) ÷ all transitions leaving A × 100. The denominator is
  `outgoingSampleSize`, reported with every row; rows under `min-transition-sample` (default 5)
  are flagged `sufficientSample: false`.
- A → A never occurs, because repeats were merged.
- These are observed shares of what followed what. They are not causal and not predictions.

**Dominant response pattern.** The most frequent *complete* sequence (any length, so a lone
`FIX` counts). `FOUND` only if it occurs in at least `min-pattern-sequences` sequences, has
at least `min-support-percent` support, and no other complete sequence has the same count.
Otherwise `INSUFFICIENT_DATA` with a reason (too rare, or tied).

**Whole analysis.** With fewer than `min-sequences` (default 3, the same minimum as the
`INSUFFICIENT_DATA` classification) complete sequences, the response is `INSUFFICIENT_DATA`
with a reason, and no patterns or transitions are returned. Unknown developer: `404`.

The thresholds are design choices, configurable in `application.properties`
(`sequence-analysis.*`), and returned in every response so a result can be read with them.
They should be reviewed with the supervisor before a study.

## 5. Comparison with the aggregate metrics

The behaviour summary counts distinct events per action and divides by all events. It is
order-blind. Two developers can have the same fix and ignore rates and still respond
differently:

| Developer | Event 1 | Event 2 |
|---|---|---|
| A | `OPEN → FIX` | `OPEN → IGNORE` |
| B | `OPEN → IGNORE → REOPEN → FIX` | `OPEN` |

Both have opened 2, fixed 1, ignored 1, so fix rate 50% and ignore rate 50%; B also has
reopened 1. The sequences show the difference: A decides once per warning, B returns to an
ignored warning and fixes it later. Transition shares show it too (B has `IGNORE → REOPEN`).
Whether such differences matter for security outcomes is the empirical question in §1.

Worked example (the synthetic fixture used in the tests and the screenshot check):
5 events — `OPEN FIX`, `OPEN FIX`, `OPEN IGNORE`, `OPEN OPEN IGNORE REOPEN FIX`, `FIX`.
- Summary: fix rate 80% (4 of 5), ignore rate 40%, reopen rate 20%.
- Sequences: 5; 1 repeat merged; dominant `OPEN → FIX` in 2 of 5 (40%).
- Patterns: `OPEN → FIX` and `OPEN → IGNORE`, 40% each; the `IGNORE → REOPEN → FIX`
  path occurs once and is not reported.
- Transitions: after `OPEN`, `FIX` 50% and `IGNORE` 50% (n = 4, small sample).

## 6. Limitations

- **Claimed fixes.** `FIX` is not proof of a fix (TASKS P1-6).
- **Coarse actions.** C1's actions are mapped to five C2 actions before storage (§2).
- **Duplicates.** Consecutive duplicates are merged, so a retried request does not create a
  pattern; but a genuine second click of the same action is merged too.
- **Timestamps are client-reported.** Order follows C1's clock; a skewed clock reorders actions.
- **Truncated histories.** If an event's earlier logs were deleted, its sequence starts
  mid-way; this cannot be detected from the logs.
- **Small samples.** Per-developer data is small; supports and probabilities from a handful of
  events are descriptive only. The thresholds and `sufficientSample` flag make this visible
  but do not make small samples reliable.
- **Developer identity** is client-asserted (TECHNICAL_OVERVIEW §9.3).
- **No sessions or time windows.** All of a developer's events are analysed together (sessions
  on events arrive with TASKS P2-3).

## 7. Reproducible test cases

All fixtures are deterministic and synthetic. No production data is read or changed.

| Test class | Checks |
|---|---|
| `ResponseSequenceAnalysisTest` (23 tests) | Ordering by time, not insertion; ties by log id; events never combined; other developers' and event-less records excluded; the same record counted once; consecutive repeats merged; `IGNORE → DISMISS` kept; missing timestamps exclude the event; the §5 worked example exactly (patterns, support, dominant, transitions); occurrences vs sequences; minimum support and sequence count; lengths 2–5; most recent occurrence; transition denominators; sufficient-sample flag; ties and rare sequences give no dominant pattern; a single-action dominant; every insufficient-data reason; invalid thresholds |
| `ResponseSequenceApiIntegrationTest` (6 tests) | The endpoint on the real stack with C1's request bodies: hand-calculated results with `SYSTEM` `DETECTED` entries present but never counted, a `409` action never counted; developers kept apart (and a `403` action never stored); no actions; unknown developer `404`; nothing written by the analysis; the behaviour summary unchanged |

Run: `cd component-2-behaviour-tracker/backend && mvn test -Dtest='ResponseSequence*'`.
