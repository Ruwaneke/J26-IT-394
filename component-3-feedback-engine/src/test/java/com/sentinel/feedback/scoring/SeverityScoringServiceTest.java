package com.sentinel.feedback.scoring;

import com.sentinel.feedback.model.BehaviourHistory;
import com.sentinel.feedback.model.SecurityEvent;
import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SeverityScoringServiceTest {

    private final SeverityScoringService service = new SeverityScoringService();

    @Test
    void scoresEachSeverityLevelAtItsBaseBoundary() {
        assertEquals(new SeverityScore(0, Severity.INFO), score(Severity.INFO, 0.5, 0));
        assertEquals(new SeverityScore(20, Severity.LOW), score(Severity.LOW, 0.5, 0));
        assertEquals(new SeverityScore(40, Severity.MEDIUM), score(Severity.MEDIUM, 0.5, 0));
        assertEquals(new SeverityScore(65, Severity.HIGH), score(Severity.HIGH, 0.5, 0));
        assertEquals(new SeverityScore(85, Severity.CRITICAL), score(Severity.CRITICAL, 0.5, 0));
    }

    @Test
    void classifiesEveryThresholdCorrectly() {
        assertEquals(Severity.INFO, score(Severity.INFO, 0.5, 3).severity());
        assertEquals(Severity.LOW, score(Severity.LOW, 0.5, 0).severity());
        assertEquals(Severity.MEDIUM, score(Severity.MEDIUM, 0.5, 0).severity());
        assertEquals(Severity.HIGH, score(Severity.HIGH, 0.5, 0).severity());
        assertEquals(Severity.CRITICAL, score(Severity.CRITICAL, 0.5, 0).severity());
    }

    @Test
    void adjustsForConfidenceAndRepeatedFindings() {
        assertEquals(55, score(Severity.MEDIUM, 0.9, 1).score());
        assertEquals(20, score(Severity.LOW, 0.4, 2).score());
        assertEquals(100, score(Severity.CRITICAL, 0.9, 10).score());
    }

    private SeverityScore score(Severity severity, double confidence, int previousFindings) {
        SecurityEvent event = new SecurityEvent(
                "event-1", "DEV001", "session-1", VulnerabilityType.SQL_INJECTION,
                severity, confidence, "Example.java", 12, Instant.parse("2026-10-14T00:00:00Z"));
        BehaviourHistory history = new BehaviourHistory(
                "DEV001", previousFindings, 0, 0,
                Map.of(VulnerabilityType.SQL_INJECTION, previousFindings));
        return service.score(event, history);
    }
}
