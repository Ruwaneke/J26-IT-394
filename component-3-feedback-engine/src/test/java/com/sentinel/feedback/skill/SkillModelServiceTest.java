package com.sentinel.feedback.skill;

import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SkillModelServiceTest {

    private static final double EPS = 1e-9;

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
    private final SkillModelService service =
            new SkillModelService(TestPolicies.defaults(), new InMemorySkillStore(), clock);

    @Test
    void fixMovesMasteryTowardOne() {
        assertEquals(0.625, service.update(0.5, SkillEventType.FIX), EPS);
        assertEquals(0.71875, service.update(0.625, SkillEventType.FIX), EPS);
    }

    @Test
    void negativeEventsShrinkMasteryProportionally() {
        assertEquals(0.425, service.update(0.5, SkillEventType.IGNORE), EPS);
        assertEquals(0.35, service.update(0.5, SkillEventType.REPEAT), EPS);
        assertEquals(0.40, service.update(0.5, SkillEventType.REOPEN), EPS);
    }

    @Test
    void decayHalvesDistanceToNeutralEveryHalfLife() {
        assertEquals(0.6, service.decay(0.7, Duration.ofDays(30)), EPS);
        assertEquals(0.45, service.decay(0.3, Duration.ofDays(60)), EPS);
        assertEquals(0.7, service.decay(0.7, Duration.ZERO), EPS);
    }

    @Test
    void masteryNeverLeavesZeroToOne() {
        double low = 0.5;
        double high = 0.5;
        for (int i = 0; i < 200; i++) {
            low = service.update(low, SkillEventType.REPEAT);
            high = service.update(high, SkillEventType.FIX);
        }
        assertTrue(low >= 0.0 && low < 0.01);
        assertTrue(high <= 1.0 && high > 0.99);
    }

    @Test
    void unknownDeveloperStartsAtInitialMastery() {
        assertEquals(0.5, service.currentMastery("d-new", "CWE-89"), EPS);
    }

    @Test
    void recordedEventsPersistAndDecayOverTime() {
        service.record("d-1", "CWE-89", SkillEventType.FIX);
        assertEquals(0.625, service.currentMastery("d-1", "CWE-89"), EPS);

        clock.advance(Duration.ofDays(30));
        assertEquals(0.5625, service.currentMastery("d-1", "CWE-89"), EPS);

        SkillState afterRepeat = service.record("d-1", "CWE-89", SkillEventType.REPEAT);
        assertEquals(0.5625 * 0.7, afterRepeat.mastery(), EPS);
        assertEquals(2, afterRepeat.eventsCount());
    }

    @Test
    void skillsAreTrackedPerCwe() {
        service.record("d-1", "CWE-89", SkillEventType.FIX);
        service.record("d-1", "CWE-79", SkillEventType.IGNORE);

        assertEquals(2, service.currentSkills("d-1").size());
        assertEquals(0.425, service.currentMastery("d-1", "CWE-79"), EPS);
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
