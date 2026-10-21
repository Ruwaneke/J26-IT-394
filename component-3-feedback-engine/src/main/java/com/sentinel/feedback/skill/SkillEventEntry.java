package com.sentinel.feedback.skill;

import java.time.Instant;

/** One mastery update, kept as an audit trail. */
public record SkillEventEntry(
        String devHash,
        String cweId,
        SkillEventType eventType,
        double masteryBefore,
        double masteryAfter,
        Instant createdAt
) {
}
