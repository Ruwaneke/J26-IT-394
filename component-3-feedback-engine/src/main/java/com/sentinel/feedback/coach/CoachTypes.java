package com.sentinel.feedback.coach;

import com.sentinel.feedback.decision.FeedbackDecision;

import java.time.Instant;
import java.util.List;

/** Request and response types for the fatigue-aware delivery API. */
public final class CoachTypes {

    private CoachTypes() {
    }

    public enum InteractionType { SHOWN, EXPANDED, DISMISSED }

    public enum OutcomeType { FIXED, IGNORED, SNOOZED }

    public enum VoteType { HELPFUL, NOT_HELPFUL, TOO_MUCH }

    public record MasteryPoint(Instant at, double mastery) {
    }

    public record Notice(Instant shownAt, boolean expanded, Instant dismissedAt, boolean quickDismiss) {
    }

    /** Everything the "Why this level?" panel needs, re-read from the stored decision. */
    public record Explanation(
            FeedbackDecision decision,
            String severity,
            String file,
            int baseLevel,
            Instant createdAt,
            List<MasteryPoint> masteryHistory,
            Notice notice
    ) {
    }

    public record OutcomeResult(String decisionId, OutcomeType outcome, long timeToOutcomeSec,
                                boolean quickFix, double masteryAfter) {
    }

    public record HourBucket(Instant hourStart, int interruptions, int notices) {
    }

    /** Alert-fatigue figures for Component 4. Fatigue index F = interruptions in the last hour / budget. */
    public record FatigueAnalytics(
            String devHash,
            int budgetPerHour,
            long interruptionsLastHour,
            double fatigueIndex,
            long decisionsLast24h,
            long quickDismissalsLast24h,
            long helpfulVotesLast24h,
            long notHelpfulVotesLast24h,
            long tooMuchVotesLast24h,
            List<HourBucket> last24Hours
    ) {
    }
}
