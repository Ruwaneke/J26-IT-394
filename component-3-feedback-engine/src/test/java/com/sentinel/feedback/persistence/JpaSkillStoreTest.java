package com.sentinel.feedback.persistence;

import com.sentinel.feedback.policy.TestPolicies;
import com.sentinel.feedback.skill.SkillEventType;
import com.sentinel.feedback.skill.SkillModelService;
import com.sentinel.feedback.testutil.MutableClock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Runs the Flyway schema on H2 and checks the store against it. */
@DataJpaTest
@Import(JpaSkillStore.class)
class JpaSkillStoreTest {

    private static final double EPS = 1e-9;

    @Autowired
    private JpaSkillStore store;

    @Autowired
    private SkillEventRepository events;

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));

    @Test
    void masteryIsSharedAcrossServiceInstances() {
        new SkillModelService(TestPolicies.defaults(), store, clock).record("d-1", "CWE-89", SkillEventType.FIX);

        // A fresh service (as after a restart) sees the persisted state.
        SkillModelService restarted = new SkillModelService(TestPolicies.defaults(), store, clock);
        assertEquals(0.625, restarted.currentMastery("d-1", "CWE-89"), EPS);
    }

    @Test
    void everyUpdateIsLoggedWithBeforeAndAfter() {
        SkillModelService service = new SkillModelService(TestPolicies.defaults(), store, clock);
        service.record("d-2", "CWE-79", SkillEventType.FIX);
        clock.advance(Duration.ofDays(1));
        service.record("d-2", "CWE-79", SkillEventType.REPEAT);

        List<SkillEventEntity> log = events.findByDevHashAndCweIdOrderByCreatedAtAscIdAsc("d-2", "CWE-79");
        assertEquals(2, log.size());
        assertEquals(SkillEventType.FIX, log.get(0).getEventType());
        assertEquals(0.5, log.get(0).getMasteryBefore(), EPS);
        assertEquals(0.625, log.get(0).getMasteryAfter(), EPS);
        assertEquals(log.get(0).getMasteryAfter(), log.get(1).getMasteryBefore(), 0.01);
        assertEquals(2, store.find("d-2", "CWE-79").orElseThrow().eventsCount());
    }

    @Test
    void listsSkillsPerDeveloperOrderedByCwe() {
        SkillModelService service = new SkillModelService(TestPolicies.defaults(), store, clock);
        service.record("d-3", "CWE-89", SkillEventType.IGNORE);
        service.record("d-3", "CWE-20", SkillEventType.FIX);
        service.record("d-other", "CWE-89", SkillEventType.FIX);

        assertEquals(List.of("CWE-20", "CWE-89"),
                store.findAll("d-3").stream().map(s -> s.cweId()).toList());
        assertTrue(store.find("d-3", "CWE-79").isEmpty());
    }
}
