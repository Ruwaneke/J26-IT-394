package com.sentinel.tracker.analysis;

import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse.ActionTransition;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse.DominantPattern;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse.SequencePattern;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.DominantPatternStatus;
import com.sentinel.tracker.enums.SequenceAnalysisStatus;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Behaviour Sequence Intelligence (TASKS P2-10): the order in which a developer responds to
 * each security event, and the response patterns that recur across events.
 *
 * <p>The input is the developer's behaviour logs only, the one record of developer actions.
 * Lifecycle history is not read: its DETECTED entry is written by SYSTEM, and every later
 * entry repeats a logged action, so reading it would count actions twice.
 *
 * <p>Sequence construction (TECHNICAL_OVERVIEW §7.4):
 * <ol>
 *   <li>One sequence per security event owned by the developer. Records without an event, or
 *       on another developer's event, are excluded.</li>
 *   <li>A record passed twice (same log id) counts once.</li>
 *   <li>Actions are ordered by action timestamp; ties by log id (insertion order).</li>
 *   <li>Consecutive identical actions are one step (a second OPEN, or a resent request).</li>
 *   <li>An event with an action that has no timestamp is excluded, since its order is unknown.</li>
 * </ol>
 *
 * <p>Plain class with no Spring or repository dependencies, so it is unit-testable.
 */
public final class ResponseSequenceAnalysis {

    public static final int MIN_PATTERN_LENGTH = 2;
    public static final int MAX_PATTERN_LENGTH = 5;

    /** One developer action, as stored in {@code behaviour_logs}. */
    public record ActionRecord(Long logId, Long securityEventId, BehaviourAction action, LocalDateTime timestamp) {
    }

    /** Evidence thresholds; see TECHNICAL_OVERVIEW §7.4. */
    public record Thresholds(int minSequences, int minPatternSequences, double minSupportPercent,
                             int minTransitionSample) {
        public Thresholds {
            if (minSequences < 1 || minPatternSequences < 1 || minTransitionSample < 1
                    || minSupportPercent < 0 || minSupportPercent > 100) {
                throw new IllegalArgumentException("Sequence-analysis thresholds must be at least 1, "
                        + "and the minimum support between 0 and 100");
            }
        }
    }

    private record Step(BehaviourAction action, LocalDateTime timestamp) {
    }

    /** Counts for one action pattern. */
    private static final class Tally {
        long occurrences;
        long sequences;
        LocalDateTime lastOccurredAt;

        void occurredAt(LocalDateTime at) {
            occurrences++;
            if (lastOccurredAt == null || at.isAfter(lastOccurredAt)) {
                lastOccurredAt = at;
            }
        }
    }

    private static final Comparator<ActionRecord> CHRONOLOGICAL = Comparator
            .comparing(ActionRecord::timestamp)
            .thenComparing(ActionRecord::logId, Comparator.nullsLast(Comparator.naturalOrder()));

    private ResponseSequenceAnalysis() {
    }

    public static ResponseSequenceAnalysisResponse analyse(Long developerId, Collection<ActionRecord> records,
                                                           Set<Long> ownEventIds, Thresholds thresholds) {
        // ── 1. Group the developer's actions by their own security event ─────
        Set<Long> seenLogIds = new HashSet<>();
        long totalRecords = 0;
        long excludedRecords = 0;
        Map<Long, List<ActionRecord>> byEvent = new TreeMap<>();
        for (ActionRecord record : records) {
            if (record.logId() != null && !seenLogIds.add(record.logId())) {
                continue;
            }
            totalRecords++;
            if (record.action() == null || record.securityEventId() == null
                    || !ownEventIds.contains(record.securityEventId())) {
                excludedRecords++;
                continue;
            }
            byEvent.computeIfAbsent(record.securityEventId(), id -> new ArrayList<>()).add(record);
        }

        // ── 2. Order each event's actions and merge consecutive repeats ──────
        long incompleteEvents = 0;
        long collapsedRepeats = 0;
        List<List<Step>> sequences = new ArrayList<>();
        for (List<ActionRecord> eventRecords : byEvent.values()) {
            if (eventRecords.stream().anyMatch(r -> r.timestamp() == null)) {
                incompleteEvents++;
                continue;
            }
            List<Step> steps = new ArrayList<>();
            for (ActionRecord record : eventRecords.stream().sorted(CHRONOLOGICAL).toList()) {
                if (!steps.isEmpty() && steps.get(steps.size() - 1).action() == record.action()) {
                    collapsedRepeats++;
                } else {
                    steps.add(new Step(record.action(), record.timestamp()));
                }
            }
            sequences.add(steps);
        }

        long totalSequences = sequences.size();
        ResponseSequenceAnalysisResponse.ResponseSequenceAnalysisResponseBuilder response =
                ResponseSequenceAnalysisResponse.builder()
                        .developerId(developerId)
                        .totalActionRecords(totalRecords)
                        .excludedActionRecords(excludedRecords)
                        .collapsedRepeatActions(collapsedRepeats)
                        .totalEligibleEvents((long) byEvent.size())
                        .totalEligibleSequences(totalSequences)
                        .excludedIncompleteEvents(incompleteEvents)
                        .singleActionSequences(sequences.stream().filter(s -> s.size() == 1).count())
                        .thresholds(ResponseSequenceAnalysisResponse.Thresholds.builder()
                                .minSequences(thresholds.minSequences())
                                .minPatternSequences(thresholds.minPatternSequences())
                                .minSupportPercent(thresholds.minSupportPercent())
                                .minTransitionSample(thresholds.minTransitionSample())
                                .build());

        // ── 3. Too little evidence: report nothing rather than weak patterns ─
        if (totalSequences < thresholds.minSequences()) {
            String reason = insufficientReason(totalRecords, byEvent.size(), totalSequences, thresholds);
            return response
                    .analysisStatus(SequenceAnalysisStatus.INSUFFICIENT_DATA)
                    .insufficientDataReason(reason)
                    .dominantPattern(DominantPattern.builder()
                            .status(DominantPatternStatus.INSUFFICIENT_DATA)
                            .eligibleSequenceCount(totalSequences)
                            .reason(reason)
                            .build())
                    .frequentPatterns(List.of())
                    .transitionAnalysis(List.of())
                    .build();
        }

        return response
                .analysisStatus(SequenceAnalysisStatus.ANALYSED)
                .dominantPattern(dominantPattern(sequences, thresholds))
                .frequentPatterns(frequentPatterns(sequences, thresholds))
                .transitionAnalysis(transitions(sequences, thresholds))
                .build();
    }

    // ── Analyses ──────────────────────────────────────────────────────────────

    /**
     * Contiguous patterns of length 2 to 5. Support = sequences containing the pattern /
     * all complete sequences × 100. Reported only when at least minPatternSequences
     * sequences contain it and its support reaches minSupportPercent.
     */
    private static List<SequencePattern> frequentPatterns(List<List<Step>> sequences, Thresholds thresholds) {
        Map<List<BehaviourAction>, Tally> tallies = new HashMap<>();
        for (List<Step> sequence : sequences) {
            Set<List<BehaviourAction>> inThisSequence = new HashSet<>();
            for (int length = MIN_PATTERN_LENGTH; length <= Math.min(MAX_PATTERN_LENGTH, sequence.size()); length++) {
                for (int start = 0; start + length <= sequence.size(); start++) {
                    List<BehaviourAction> pattern = actions(sequence.subList(start, start + length));
                    Tally tally = tallies.computeIfAbsent(pattern, p -> new Tally());
                    tally.occurredAt(sequence.get(start + length - 1).timestamp());
                    if (inThisSequence.add(pattern)) {
                        tally.sequences++;
                    }
                }
            }
        }

        long total = sequences.size();
        return tallies.entrySet().stream()
                .filter(e -> e.getValue().sequences >= thresholds.minPatternSequences())
                .filter(e -> percent(e.getValue().sequences, total) >= thresholds.minSupportPercent())
                .sorted(Comparator
                        .comparing((Map.Entry<List<BehaviourAction>, Tally> e) -> e.getValue().sequences).reversed()
                        .thenComparing(e -> e.getValue().occurrences, Comparator.reverseOrder())
                        .thenComparing(e -> e.getKey().size(), Comparator.reverseOrder())
                        .thenComparing(e -> e.getKey().toString()))
                .map(e -> SequencePattern.builder()
                        .actions(e.getKey())
                        .length(e.getKey().size())
                        .occurrenceCount(e.getValue().occurrences)
                        .sequenceCount(e.getValue().sequences)
                        .supportPercent(percent(e.getValue().sequences, total))
                        .eligibleSequenceCount(total)
                        .lastOccurredAt(e.getValue().lastOccurredAt)
                        .build())
                .toList();
    }

    /**
     * The most frequent complete sequence (all actions on one event, any length). FOUND only
     * if it is the single most frequent one and meets the same thresholds as a pattern.
     */
    private static DominantPattern dominantPattern(List<List<Step>> sequences, Thresholds thresholds) {
        Map<List<BehaviourAction>, Tally> tallies = new HashMap<>();
        for (List<Step> sequence : sequences) {
            Tally tally = tallies.computeIfAbsent(actions(sequence), p -> new Tally());
            tally.occurredAt(sequence.get(sequence.size() - 1).timestamp());
            tally.sequences++;
        }

        long total = sequences.size();
        long top = tallies.values().stream().mapToLong(t -> t.sequences).max().orElse(0);
        List<Map.Entry<List<BehaviourAction>, Tally>> leaders = tallies.entrySet().stream()
                .filter(e -> e.getValue().sequences == top)
                .toList();
        DominantPattern.DominantPatternBuilder dominant = DominantPattern.builder().eligibleSequenceCount(total);

        if (top < thresholds.minPatternSequences() || percent(top, total) < thresholds.minSupportPercent()) {
            return dominant.status(DominantPatternStatus.INSUFFICIENT_DATA)
                    .reason(String.format("No complete response sequence recurs often enough: the most frequent "
                                    + "occurs in %d of %d sequences (minimum %d sequences and %s%% support)",
                            top, total, thresholds.minPatternSequences(), format(thresholds.minSupportPercent())))
                    .build();
        }
        if (leaders.size() > 1) {
            return dominant.status(DominantPatternStatus.INSUFFICIENT_DATA)
                    .reason(String.format("%d different complete sequences are tied at %d of %d sequences each; "
                            + "no single sequence dominates", leaders.size(), top, total))
                    .build();
        }
        Map.Entry<List<BehaviourAction>, Tally> leader = leaders.get(0);
        return dominant.status(DominantPatternStatus.FOUND)
                .actions(leader.getKey())
                .occurrenceCount(leader.getValue().sequences)
                .supportPercent(percent(leader.getValue().sequences, total))
                .lastOccurredAt(leader.getValue().lastOccurredAt)
                .build();
    }

    /**
     * Consecutive action pairs within each sequence. Probability = transitions from A to B /
     * all transitions leaving A × 100. Repeats were merged, so A never follows itself.
     */
    private static List<ActionTransition> transitions(List<List<Step>> sequences, Thresholds thresholds) {
        Map<BehaviourAction, Map<BehaviourAction, Long>> counts = new EnumMap<>(BehaviourAction.class);
        for (List<Step> sequence : sequences) {
            for (int i = 0; i + 1 < sequence.size(); i++) {
                counts.computeIfAbsent(sequence.get(i).action(), a -> new EnumMap<>(BehaviourAction.class))
                        .merge(sequence.get(i + 1).action(), 1L, Long::sum);
            }
        }

        List<ActionTransition> transitions = new ArrayList<>();
        counts.forEach((from, targets) -> {
            long outgoing = targets.values().stream().mapToLong(Long::longValue).sum();
            targets.entrySet().stream()
                    .sorted(Map.Entry.<BehaviourAction, Long>comparingByValue().reversed()
                            .thenComparing(Map.Entry.comparingByKey()))
                    .forEach(target -> transitions.add(ActionTransition.builder()
                            .fromAction(from)
                            .toAction(target.getKey())
                            .transitionCount(target.getValue())
                            .outgoingSampleSize(outgoing)
                            .probabilityPercent(percent(target.getValue(), outgoing))
                            .sufficientSample(outgoing >= thresholds.minTransitionSample())
                            .build()));
        });
        return transitions;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String insufficientReason(long records, long eligibleEvents, long sequences, Thresholds thresholds) {
        if (records == 0) {
            return "No developer actions are recorded for this developer";
        }
        if (eligibleEvents == 0) {
            return String.format("None of the %d recorded actions belongs to one of the developer's own "
                    + "security events", records);
        }
        return String.format("Only %d complete response sequence%s; at least %d are needed",
                sequences, sequences == 1 ? "" : "s", thresholds.minSequences());
    }

    private static List<BehaviourAction> actions(List<Step> steps) {
        return steps.stream().map(Step::action).toList();
    }

    /** Percentage rounded to one decimal, as in the behaviour summary. */
    private static double percent(long count, long total) {
        return total == 0 ? 0.0 : Math.round((double) count / total * 100.0 * 10.0) / 10.0;
    }

    private static String format(double value) {
        return value == Math.rint(value) ? String.valueOf((long) value) : String.valueOf(value);
    }
}
