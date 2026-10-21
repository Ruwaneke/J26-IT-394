package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.recommendation.RecommendationTemplateService;
import com.sentinel.feedback.skill.SkillModelService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Rules decide: skill lookup, priority score, level mapping and a static template. */
@Service
public class DecisionService {

    private final PolicyProperties policy;
    private final SkillModelService skillModel;
    private final ScoringService scoring;
    private final LevelMapper levelMapper;
    private final RecommendationTemplateService templates;

    public DecisionService(
            PolicyProperties policy,
            SkillModelService skillModel,
            ScoringService scoring,
            LevelMapper levelMapper,
            RecommendationTemplateService templates) {
        this.policy = policy;
        this.skillModel = skillModel;
        this.scoring = scoring;
        this.levelMapper = levelMapper;
        this.templates = templates;
    }

    public FeedbackDecision decide(FeedbackEvent event, DeveloperHistory history) {
        VulnerabilityType type = VulnerabilityType.fromCwe(event.cwe());
        double mastery = skillModel.currentMastery(history.devHash(), type.cweId());

        ScoreBreakdown breakdown = scoring.compute(event.severity(), history, mastery).rounded();
        double score = ScoreBreakdown.round2(breakdown.total());
        LevelMapper.LevelDecision level =
                levelMapper.decide(score, type, event.severity(), mastery, history);

        return new FeedbackDecision(
                "dec-" + UUID.randomUUID(),
                event.eventId(),
                type.cweId(),
                level.level().number(),
                level.level().displayName(),
                score,
                breakdown,
                ScoreBreakdown.round2(mastery),
                reasons(type, history, mastery),
                level.adjustments(),
                policy.version(),
                templates.getTemplate(type));
    }

    private List<String> reasons(VulnerabilityType type, DeveloperHistory history, double mastery) {
        List<String> reasons = new ArrayList<>();
        if (history.repeats30d() > 0) {
            reasons.add(count(history.repeats30d(), "repeat") + " in 30 days");
        }
        if (history.reopened30d() > 0) {
            reasons.add(count(history.reopened30d(), "reopened fix") + " in 30 days");
        }
        if (history.ignored30d() > 0) {
            reasons.add(count(history.ignored30d(), "ignored warning") + " in 30 days");
        }
        if (history.lastSimilarDaysAgo() != null
                && history.lastSimilarDaysAgo() <= policy.recency().halfDays()) {
            reasons.add("Similar issue " + count(history.lastSimilarDaysAgo(), "day") + " ago");
        }
        if (reasons.isEmpty()) {
            reasons.add("No recent history for this issue");
        }
        reasons.add(String.format(Locale.ROOT, "Mastery for %s: %.2f", type.cweId(), mastery));
        return List.copyOf(reasons);
    }

    private static String count(int n, String noun) {
        String plural = noun.endsWith("x") ? noun + "es" : noun + "s";
        return n + " " + (n == 1 ? noun : plural);
    }
}
