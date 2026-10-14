package com.sentinel.feedback.scoring;

import com.sentinel.feedback.model.BehaviourHistory;
import com.sentinel.feedback.model.SecurityEvent;
import com.sentinel.feedback.model.Severity;
import org.springframework.stereotype.Service;

@Service
public class SeverityScoringService {

    public SeverityScore score(SecurityEvent event, BehaviourHistory history) {
        int score = baseScore(event.severity());
        score += confidenceAdjustment(event.confidence());
        score += Math.min(history.previousFindingsFor(event.vulnerabilityType()) * 5, 15);
        return classify(clamp(score));
    }

    private int baseScore(Severity severity) {
        return switch (severity) {
            case INFO -> 0;
            case LOW -> 20;
            case MEDIUM -> 40;
            case HIGH -> 65;
            case CRITICAL -> 85;
        };
    }

    private int confidenceAdjustment(double confidence) {
        if (confidence < 0 || confidence > 1) {
            throw new IllegalArgumentException("Confidence must be between 0.0 and 1.0");
        }
        if (confidence < 0.5) {
            return -10;
        }
        if (confidence >= 0.9) {
            return 10;
        }
        return 0;
    }

    private int clamp(int score) {
        return Math.max(0, Math.min(100, score));
    }

    private SeverityScore classify(int score) {
        Severity severity;
        if (score < 20) {
            severity = Severity.INFO;
        } else if (score < 40) {
            severity = Severity.LOW;
        } else if (score < 60) {
            severity = Severity.MEDIUM;
        } else if (score < 80) {
            severity = Severity.HIGH;
        } else {
            severity = Severity.CRITICAL;
        }
        return new SeverityScore(score, severity);
    }
}
