package com.sentinel.feedback.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "feedback_decision")
public class FeedbackDecisionEntity {

    @Id
    private String id;

    @Column(name = "event_id", nullable = false)
    private String eventId;

    @Column(name = "dev_hash", nullable = false)
    private String devHash;

    @Column(name = "cwe_id", nullable = false)
    private String cweId;

    @Column(nullable = false)
    private String severity;

    /** File the finding was in; empty when Component 1 did not send one. */
    @Column(name = "file_ref", nullable = false)
    private String fileRef;

    @Column(nullable = false)
    private double score;

    @Column(name = "base_level", nullable = false)
    private int baseLevel;

    @Column(nullable = false)
    private int level;

    @Column(nullable = false)
    private String channel;

    @Column(nullable = false)
    private boolean interruptive;

    @Column(nullable = false)
    private double mastery;

    @Column(name = "breakdown_json", nullable = false)
    private String breakdownJson;

    @Column(name = "reasons_json", nullable = false)
    private String reasonsJson;

    @Column(name = "adjustments_json", nullable = false)
    private String adjustmentsJson;

    @Column(name = "delivery_notes_json", nullable = false)
    private String deliveryNotesJson;

    @Column(nullable = false)
    private String narrative;

    @Column(name = "policy_version", nullable = false)
    private String policyVersion;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected FeedbackDecisionEntity() {
    }

    @SuppressWarnings("java:S107")
    public FeedbackDecisionEntity(String id, String eventId, String devHash, String cweId, String severity,
                                  String fileRef, double score, int baseLevel, int level, String channel,
                                  boolean interruptive, double mastery, String breakdownJson, String reasonsJson,
                                  String adjustmentsJson, String deliveryNotesJson, String narrative,
                                  String policyVersion, Instant createdAt) {
        this.id = id;
        this.eventId = eventId;
        this.devHash = devHash;
        this.cweId = cweId;
        this.severity = severity;
        this.fileRef = fileRef;
        this.score = score;
        this.baseLevel = baseLevel;
        this.level = level;
        this.channel = channel;
        this.interruptive = interruptive;
        this.mastery = mastery;
        this.breakdownJson = breakdownJson;
        this.reasonsJson = reasonsJson;
        this.adjustmentsJson = adjustmentsJson;
        this.deliveryNotesJson = deliveryNotesJson;
        this.narrative = narrative;
        this.policyVersion = policyVersion;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getEventId() { return eventId; }
    public String getDevHash() { return devHash; }
    public String getCweId() { return cweId; }
    public String getSeverity() { return severity; }
    public String getFileRef() { return fileRef; }
    public double getScore() { return score; }
    public int getBaseLevel() { return baseLevel; }
    public int getLevel() { return level; }
    public String getChannel() { return channel; }
    public boolean isInterruptive() { return interruptive; }
    public double getMastery() { return mastery; }
    public String getBreakdownJson() { return breakdownJson; }
    public String getReasonsJson() { return reasonsJson; }
    public String getAdjustmentsJson() { return adjustmentsJson; }
    public String getDeliveryNotesJson() { return deliveryNotesJson; }
    public String getNarrative() { return narrative; }
    public String getPolicyVersion() { return policyVersion; }
    public Instant getCreatedAt() { return createdAt; }
}
