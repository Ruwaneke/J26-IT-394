package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Reproduces the worked example in the plan (Section 4.3): same SQLi, three developers. */
class ScoringServiceTest {

    private final ScoringService scoring = new ScoringService(TestPolicies.defaults());
    private final LevelMapper mapper = new LevelMapper(TestPolicies.defaults());

    @Test
    void developerAFirstTimeGetsGuide() {
        ScoreBreakdown breakdown = scoring.compute(Severity.HIGH,
                new DeveloperHistory("A", 0, 0, 0, 0, null), 0.50).rounded();

        assertEquals(new ScoreBreakdown(26.25, 0, 0, 7.5, 0), breakdown);
        assertEquals(33.75, ScoreBreakdown.round2(breakdown.total()));
        assertEquals(FeedbackLevel.L2, mapper.map(breakdown.total()));
    }

    @Test
    void developerBRepeatedWithTwoIgnoresGetsCoach() {
        ScoreBreakdown breakdown = scoring.compute(Severity.HIGH,
                new DeveloperHistory("B", 3, 2, 0, 0, 2), 0.32).rounded();

        assertEquals(new ScoreBreakdown(26.25, 20, 13.33, 10.2, 10), breakdown);
        assertEquals(79.78, ScoreBreakdown.round2(breakdown.total()));
        assertEquals(FeedbackLevel.L3, mapper.map(breakdown.total()));
    }

    @Test
    void developerCRepeatedWithThreeIgnoresGetsIntervene() {
        ScoreBreakdown breakdown = scoring.compute(Severity.HIGH,
                new DeveloperHistory("C", 3, 3, 0, 0, 2), 0.32).rounded();

        assertEquals(86.45, ScoreBreakdown.round2(breakdown.total()));
        assertEquals(FeedbackLevel.L4, mapper.map(breakdown.total()));
    }

    @Test
    void pressureSaturatesAtThreeEvents() {
        assertEquals(1.0, scoring.pressure(3));
        assertEquals(1.0, scoring.pressure(10));
        assertEquals(1.0 / 3, scoring.pressure(1), 1e-9);
    }

    @Test
    void recencyStepsAtSevenAndFourteenDays() {
        assertEquals(0.0, scoring.recency(null));
        assertEquals(1.0, scoring.recency(7));
        assertEquals(0.5, scoring.recency(8));
        assertEquals(0.5, scoring.recency(14));
        assertEquals(0.0, scoring.recency(15));
    }

    @Test
    void maximumInputsScoreOneHundred() {
        ScoreBreakdown breakdown = scoring.compute(Severity.CRITICAL,
                new DeveloperHistory("X", 5, 5, 0, 0, 0), 0.0);

        assertEquals(100.0, breakdown.total(), 1e-9);
    }
}
