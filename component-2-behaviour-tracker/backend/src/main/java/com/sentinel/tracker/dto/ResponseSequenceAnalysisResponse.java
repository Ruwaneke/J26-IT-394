package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.DominantPatternStatus;
import com.sentinel.tracker.enums.SequenceAnalysisStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Response DTO for Behaviour Sequence Intelligence (TASKS P2-10): the order in which a
 * developer responds to each security event, and the patterns that recur across events.
 *
 * Every percentage is over {@code totalEligibleSequences} unless stated otherwise. The
 * results are descriptive counts, not predictions.
 */
@Data
@Builder
public class ResponseSequenceAnalysisResponse {

    private Long developerId;
    private SequenceAnalysisStatus analysisStatus;
    /** Why the analysis or a part of it is not reported; null when ANALYSED. */
    private String insufficientDataReason;

    // ── Data used ─────────────────────────────────────────────────────────────

    /** Developer action records (behaviour logs) read for this developer. */
    private Long totalActionRecords;
    /** Records not tied to one of the developer's own security events. */
    private Long excludedActionRecords;
    /** Consecutive repeats of the same action on one event, merged into one step. */
    private Long collapsedRepeatActions;
    /** The developer's own security events with at least one action. */
    private Long totalEligibleEvents;
    /** Eligible events whose actions can all be ordered: one complete response sequence each. */
    private Long totalEligibleSequences;
    /** Eligible events left out because an action has no timestamp. */
    private Long excludedIncompleteEvents;
    /** Complete sequences with one action only (no pattern or transition can be formed). */
    private Long singleActionSequences;

    private Thresholds thresholds;

    // ── Results ───────────────────────────────────────────────────────────────

    private DominantPattern dominantPattern;
    private List<SequencePattern> frequentPatterns;
    private List<ActionTransition> transitionAnalysis;

    /** Evidence thresholds applied (configurable, see TECHNICAL_OVERVIEW §7.4). */
    @Data
    @Builder
    public static class Thresholds {
        private Integer minSequences;
        private Integer minPatternSequences;
        private Double minSupportPercent;
        private Integer minTransitionSample;
    }

    /** The most frequent complete response sequence, or INSUFFICIENT_DATA. */
    @Data
    @Builder
    public static class DominantPattern {
        private DominantPatternStatus status;
        /** Null unless FOUND. */
        private List<BehaviourAction> actions;
        /** Complete sequences equal to {@code actions}; null unless FOUND. */
        private Long occurrenceCount;
        private Double supportPercent;
        private Long eligibleSequenceCount;
        private LocalDateTime lastOccurredAt;
        /** Null when FOUND. */
        private String reason;
    }

    /** A contiguous action pattern (length 2 to 5) that recurs across sequences. */
    @Data
    @Builder
    public static class SequencePattern {
        private List<BehaviourAction> actions;
        private Integer length;
        /** Every contiguous occurrence, including repeats inside one sequence. */
        private Long occurrenceCount;
        /** Sequences containing the pattern at least once (the support numerator). */
        private Long sequenceCount;
        private Double supportPercent;
        private Long eligibleSequenceCount;
        private LocalDateTime lastOccurredAt;
    }

    /** One step from an action to the next on the same event. */
    @Data
    @Builder
    public static class ActionTransition {
        private BehaviourAction fromAction;
        private BehaviourAction toAction;
        private Long transitionCount;
        /** All transitions leaving {@code fromAction} (the probability denominator). */
        private Long outgoingSampleSize;
        /** transitionCount / outgoingSampleSize × 100. Observed share, not a prediction. */
        private Double probabilityPercent;
        /** Whether outgoingSampleSize reaches the minTransitionSample threshold. */
        private Boolean sufficientSample;
    }
}
