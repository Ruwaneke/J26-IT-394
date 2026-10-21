package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Maps a priority score to L1-L4, then lowers it by at most one level for good behaviour
 * (mastery relief, or else a streak of quick fixes) and finally applies the policy's hard
 * floors. Floors run last so nothing can push a secret below its minimum, and the two
 * good-behaviour rules never stack because they rest on the same evidence.
 */
@Service
public class LevelMapper {

    private final PolicyProperties policy;

    public LevelMapper(PolicyProperties policy) {
        this.policy = policy;
    }

    public FeedbackLevel map(double score) {
        PolicyProperties.Levels levels = policy.levels();
        if (score >= levels.l4()) {
            return FeedbackLevel.L4;
        }
        if (score >= levels.l3()) {
            return FeedbackLevel.L3;
        }
        if (score >= levels.l2()) {
            return FeedbackLevel.L2;
        }
        return FeedbackLevel.L1;
    }

    public LevelDecision decide(
            double score,
            VulnerabilityType type,
            Severity severity,
            double mastery,
            DeveloperHistory history) {
        return decide(score, type, severity, mastery, history, false);
    }

    public LevelDecision decide(
            double score,
            VulnerabilityType type,
            Severity severity,
            double mastery,
            DeveloperHistory history,
            boolean quickFixStreak) {
        FeedbackLevel base = map(score);
        int level = base.number();
        List<String> adjustments = new ArrayList<>();

        if (mastery >= policy.mastery().masteredThreshold() && history.ignored30d() == 0
                && level > 1) {
            level--;
            adjustments.add(String.format(Locale.ROOT,
                    "Lowered from L%d to L%d: mastery %.2f and no recent ignored warnings",
                    level + 1, level, mastery));
        } else if (quickFixStreak && level > 1) {
            level--;
            adjustments.add(String.format(Locale.ROOT,
                    "Lowered from L%d to L%d: the last %d warnings for this issue were fixed within %d minutes",
                    level + 1, level, policy.fatigue().deEscalationQuickFixes(),
                    policy.fatigue().quickFixMinutes()));
        }

        for (PolicyProperties.LevelOverride override : policy.overrides()) {
            if (matches(override, type, severity) && level < override.minLevel()) {
                adjustments.add(String.format(Locale.ROOT, "Raised from L%d to L%d: %s",
                        level, override.minLevel(), override.reason()));
                level = override.minLevel();
            }
        }

        return new LevelDecision(base, FeedbackLevel.of(level), List.copyOf(adjustments));
    }

    private boolean matches(PolicyProperties.LevelOverride override, VulnerabilityType type,
                            Severity severity) {
        boolean cweMatches = override.cwe() == null || override.cwe().equalsIgnoreCase(type.cweId());
        boolean severityMatches = override.severity() == null || override.severity() == severity;
        return cweMatches && severityMatches;
    }

    public record LevelDecision(FeedbackLevel baseLevel, FeedbackLevel level, List<String> adjustments) {
    }
}
