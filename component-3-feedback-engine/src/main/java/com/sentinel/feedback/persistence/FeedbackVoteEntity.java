package com.sentinel.feedback.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "feedback_vote")
public class FeedbackVoteEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "decision_id", nullable = false)
    private String decisionId;

    @Column(name = "dev_hash", nullable = false)
    private String devHash;

    @Column(nullable = false)
    private String vote;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected FeedbackVoteEntity() {
    }

    public FeedbackVoteEntity(String decisionId, String devHash, String vote, Instant createdAt) {
        this.decisionId = decisionId;
        this.devHash = devHash;
        this.vote = vote;
        this.createdAt = createdAt;
    }

    public String getVote() { return vote; }
}
