package com.sentinel.feedback.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "feedback_outcome")
public class FeedbackOutcomeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "decision_id", nullable = false, unique = true)
    private String decisionId;

    @Column(name = "dev_hash", nullable = false)
    private String devHash;

    @Column(name = "cwe_id", nullable = false)
    private String cweId;

    @Column(nullable = false)
    private String outcome;

    @Column(name = "time_to_outcome_sec", nullable = false)
    private long timeToOutcomeSec;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected FeedbackOutcomeEntity() {
    }

    public FeedbackOutcomeEntity(String decisionId, String devHash, String cweId, String outcome,
                                 long timeToOutcomeSec, Instant createdAt) {
        this.decisionId = decisionId;
        this.devHash = devHash;
        this.cweId = cweId;
        this.outcome = outcome;
        this.timeToOutcomeSec = timeToOutcomeSec;
        this.createdAt = createdAt;
    }

    public String getDecisionId() { return decisionId; }
    public String getOutcome() { return outcome; }
    public long getTimeToOutcomeSec() { return timeToOutcomeSec; }
    public Instant getCreatedAt() { return createdAt; }
}
