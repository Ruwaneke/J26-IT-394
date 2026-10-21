package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LevelMapperTest {

    private static final DeveloperHistory NO_IGNORES = new DeveloperHistory("d", 0, 0, 0, 0, null);
    private static final DeveloperHistory ONE_IGNORE = new DeveloperHistory("d", 0, 1, 0, 0, null);

    private final LevelMapper mapper = new LevelMapper(TestPolicies.defaults());

    @Test
    void mapsLevelBoundaries() {
        assertEquals(FeedbackLevel.L1, mapper.map(29.99));
        assertEquals(FeedbackLevel.L2, mapper.map(30));
        assertEquals(FeedbackLevel.L2, mapper.map(54.99));
        assertEquals(FeedbackLevel.L3, mapper.map(55));
        assertEquals(FeedbackLevel.L3, mapper.map(79.99));
        assertEquals(FeedbackLevel.L4, mapper.map(80));
        assertEquals(FeedbackLevel.L4, mapper.map(100));
    }

    @Test
    void hardcodedSecretIsAtLeastCoachOnFirstOccurrence() {
        LevelMapper.LevelDecision decision = mapper.decide(
                20, VulnerabilityType.HARDCODED_SECRET, Severity.LOW, 0.5, NO_IGNORES);

        assertEquals(FeedbackLevel.L1, decision.baseLevel());
        assertEquals(FeedbackLevel.L3, decision.level());
        assertTrue(decision.adjustments().get(0).startsWith("Raised from L1 to L3"));
    }

    @Test
    void criticalSeverityIsAtLeastGuide() {
        LevelMapper.LevelDecision decision = mapper.decide(
                10, VulnerabilityType.XSS, Severity.CRITICAL, 0.5, NO_IGNORES);

        assertEquals(FeedbackLevel.L2, decision.level());
    }

    @Test
    void masteryReliefLowersOneLevelWithoutRecentIgnores() {
        LevelMapper.LevelDecision decision = mapper.decide(
                60, VulnerabilityType.SQL_INJECTION, Severity.HIGH, 0.80, NO_IGNORES);

        assertEquals(FeedbackLevel.L3, decision.baseLevel());
        assertEquals(FeedbackLevel.L2, decision.level());
    }

    @Test
    void noMasteryReliefWhenWarningsWereIgnored() {
        LevelMapper.LevelDecision decision = mapper.decide(
                60, VulnerabilityType.SQL_INJECTION, Severity.HIGH, 0.80, ONE_IGNORE);

        assertEquals(FeedbackLevel.L3, decision.level());
        assertTrue(decision.adjustments().isEmpty());
    }

    @Test
    void masteryReliefNeverGoesBelowNudge() {
        LevelMapper.LevelDecision decision = mapper.decide(
                10, VulnerabilityType.SQL_INJECTION, Severity.LOW, 0.95, NO_IGNORES);

        assertEquals(FeedbackLevel.L1, decision.level());
    }

    @Test
    void masteryReliefCannotPushSecretBelowItsFloor() {
        LevelMapper.LevelDecision decision = mapper.decide(
                60, VulnerabilityType.HARDCODED_SECRET, Severity.HIGH, 0.90, NO_IGNORES);

        assertEquals(FeedbackLevel.L3, decision.level());
    }
}
