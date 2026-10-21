package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Maps a priority score to L1-L4, then applies mastery relief and the policy's hard
 * floors. Floors run last so that relief can never push a secret below its minimum.
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
        FeedbackLevel base = map(score);
        int level = base.number();
        List<String> adjustments = new ArrayList<>();

        if (mastery >= policy.mastery().masteredThreshold() && history.ignored30d() == 0
                && level > 1) {
            level--;
            adjustments.add(String.format(Locale.ROOT,
                    "Lowered from L%d to L%d: mastery %.2f and no recent ignored warnings",
                    level + 1, level, mastery));
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
