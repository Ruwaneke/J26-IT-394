package com.sentinel.feedback.decision;

import com.sentinel.feedback.recommendation.RecommendationTemplate;

import java.util.List;

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
        RecommendationTemplate template
) {
}
