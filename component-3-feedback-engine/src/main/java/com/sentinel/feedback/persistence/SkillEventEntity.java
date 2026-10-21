package com.sentinel.feedback.persistence;

import com.sentinel.feedback.skill.SkillEventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "skill_event")
public class SkillEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "dev_hash", nullable = false)
    private String devHash;

    @Column(name = "cwe_id", nullable = false)
    private String cweId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    private SkillEventType eventType;

    @Column(name = "mastery_before", nullable = false)
    private double masteryBefore;

    @Column(name = "mastery_after", nullable = false)
    private double masteryAfter;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected SkillEventEntity() {
    }

    public SkillEventEntity(String devHash, String cweId, SkillEventType eventType,
                            double masteryBefore, double masteryAfter, Instant createdAt) {
        this.devHash = devHash;
        this.cweId = cweId;
        this.eventType = eventType;
        this.masteryBefore = masteryBefore;
        this.masteryAfter = masteryAfter;
        this.createdAt = createdAt;
    }

    public SkillEventType getEventType() {
        return eventType;
    }

    public double getMasteryBefore() {
        return masteryBefore;
    }

    public double getMasteryAfter() {
        return masteryAfter;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
