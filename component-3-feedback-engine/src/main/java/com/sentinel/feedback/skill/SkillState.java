package com.sentinel.feedback.skill;

import java.time.Instant;

/** Stored mastery for one (developer, CWE) pair, as of {@code lastEventAt}. */
public record SkillState(
        String devHash,
        String cweId,
        double mastery,
        int eventsCount,
        Instant lastEventAt
) {
}
