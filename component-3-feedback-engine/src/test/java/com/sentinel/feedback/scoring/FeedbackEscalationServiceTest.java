package com.sentinel.feedback.scoring;

import com.sentinel.feedback.model.BehaviourHistory;
import com.sentinel.feedback.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FeedbackEscalationServiceTest {

    private final FeedbackEscalationService service = new FeedbackEscalationService();

    @Test
    void escalatesFeedbackAfterRepeatedIgnoredWarnings() {
        SeverityScore result = service.apply(
                new SeverityScore(65, Severity.HIGH),
                history(0, 2));

        assertEquals(new SeverityScore(65, Severity.CRITICAL), result);
    }

    @Test
    void reducesFeedbackAfterConsistentFixes() {
        SeverityScore result = service.apply(
                new SeverityScore(65, Severity.HIGH),
                history(3, 0));

        assertEquals(new SeverityScore(65, Severity.MEDIUM), result);
    }

    @Test
    void keepsFeedbackUnchangedAtBehaviourThresholdsBelowTheRules() {
        SeverityScore score = new SeverityScore(40, Severity.MEDIUM);

        assertEquals(score, service.apply(score, history(2, 1)));
    }

    @Test
    void doesNotEscalateCriticalOrReduceInfoBeyondAvailableLevels() {
        assertEquals(
                Severity.CRITICAL,
                service.apply(new SeverityScore(100, Severity.CRITICAL), history(0, 2)).severity());
        assertEquals(
                Severity.INFO,
                service.apply(new SeverityScore(0, Severity.INFO), history(3, 0)).severity());
    }

    private BehaviourHistory history(int fixes, int ignores) {
        return new BehaviourHistory("DEV001", 0, fixes, ignores, Map.of());
    }
}
