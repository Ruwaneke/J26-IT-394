package com.sentinel.feedback.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

@Entity
@Table(name = "dev_skill")
@IdClass(DevSkillEntity.Key.class)
public class DevSkillEntity {

    @Id
    @Column(name = "dev_hash")
    private String devHash;

    @Id
    @Column(name = "cwe_id")
    private String cweId;

    @Column(nullable = false)
    private double mastery;

    @Column(name = "events_count", nullable = false)
    private int eventsCount;

    @Column(name = "last_event_at", nullable = false)
    private Instant lastEventAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected DevSkillEntity() {
    }

    public DevSkillEntity(String devHash, String cweId) {
        this.devHash = devHash;
        this.cweId = cweId;
    }

    public String getDevHash() {
        return devHash;
    }

    public String getCweId() {
        return cweId;
    }

    public double getMastery() {
        return mastery;
    }

    public int getEventsCount() {
        return eventsCount;
    }

    public Instant getLastEventAt() {
        return lastEventAt;
    }

    public void update(double mastery, int eventsCount, Instant lastEventAt) {
        this.mastery = mastery;
        this.eventsCount = eventsCount;
        this.lastEventAt = lastEventAt;
        this.updatedAt = lastEventAt;
    }

    public static class Key implements Serializable {
        private String devHash;
        private String cweId;

        protected Key() {
        }

        public Key(String devHash, String cweId) {
            this.devHash = devHash;
            this.cweId = cweId;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key
                    && Objects.equals(devHash, key.devHash)
                    && Objects.equals(cweId, key.cweId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(devHash, cweId);
        }
    }
}
