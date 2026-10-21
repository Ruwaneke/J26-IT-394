package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Service;

/**
 * Priority score P = wS*S + wR*Rn + wI*In + wW*(1 - M) + wRec*Rec, with every term
 * reported separately so the "Why this level?" panel can show it.
 */
@Service
public class ScoringService {

    private final PolicyProperties policy;

    public ScoringService(PolicyProperties policy) {
        this.policy = policy;
    }

    public ScoreBreakdown compute(Severity severity, DeveloperHistory history, double mastery) {
        PolicyProperties.Weights weights = policy.weights();
        return new ScoreBreakdown(
                weights.severity() * severityFactor(severity),
                weights.repeat() * pressure(history.repeats30d()),
                weights.ignore() * pressure(history.ignored30d()),
                weights.weakness() * (1 - mastery),
                weights.recency() * recency(history.lastSimilarDaysAgo()));
    }

    double severityFactor(Severity severity) {
        return switch (severity) {
            case INFO -> 0.0;
            case LOW -> 0.25;
            case MEDIUM -> 0.5;
            case HIGH -> 0.75;
            case CRITICAL -> 1.0;
        };
    }

    double pressure(int count) {
        return Math.min((double) count / policy.pressureSaturation(), 1.0);
    }

    double recency(Integer lastSimilarDaysAgo) {
        if (lastSimilarDaysAgo == null) {
            return 0.0;
        }
        if (lastSimilarDaysAgo <= policy.recency().fullDays()) {
            return 1.0;
        }
        if (lastSimilarDaysAgo <= policy.recency().halfDays()) {
            return 0.5;
        }
        return 0.0;
    }
}
