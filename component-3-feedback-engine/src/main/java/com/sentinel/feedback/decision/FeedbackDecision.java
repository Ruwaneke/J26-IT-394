package com.sentinel.feedback.decision;

import com.sentinel.feedback.recommendation.RecommendationTemplate;

import java.util.List;

/**
 * A rule-based feedback decision. {@code channel}, {@code deliveryNotes} and
 * {@code narrative} are filled in by the fatigue-aware delivery stage (Plan B).
 */
public record FeedbackDecision(
        String decisionId,
        String eventId,
        String cwe,
        int level,
        String levelName,
        double score,
        ScoreBreakdown breakdown,
        double mastery,
        List<String> reasons,
        List<String> adjustments,
        String policyVersion,
        RecommendationTemplate template,
        Channel channel,
        List<String> deliveryNotes,
        String narrative
) {
    public FeedbackDecision withDelivery(Channel channel, List<String> deliveryNotes, String narrative) {
        return new FeedbackDecision(decisionId, eventId, cwe, level, levelName, score, breakdown, mastery,
                reasons, adjustments, policyVersion, template, channel, List.copyOf(deliveryNotes), narrative);
    }
}
