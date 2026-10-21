package com.sentinel.feedback.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** One row per decision: what the IDE reported about the notice. */
@Entity
@Table(name = "notice_log")
public class NoticeLogEntity {

    @Id
    @Column(name = "decision_id")
    private String decisionId;

    @Column(name = "shown_at")
    private Instant shownAt;

    @Column(nullable = false)
    private boolean expanded;

    @Column(name = "dismissed_at")
    private Instant dismissedAt;

    @Column(name = "quick_dismiss", nullable = false)
    private boolean quickDismiss;

    protected NoticeLogEntity() {
    }

    public NoticeLogEntity(String decisionId) {
        this.decisionId = decisionId;
    }

    public String getDecisionId() { return decisionId; }
    public Instant getShownAt() { return shownAt; }
    public boolean isExpanded() { return expanded; }
    public Instant getDismissedAt() { return dismissedAt; }
    public boolean isQuickDismiss() { return quickDismiss; }

    public void markShown(Instant at) {
        if (shownAt == null) {
            shownAt = at;
        }
    }

    public void markExpanded() {
        expanded = true;
    }

    /** A dismissal counts as quick when it happens soon after showing and without expanding. */
    public void markDismissed(Instant at, long quickDismissSeconds) {
        dismissedAt = at;
        quickDismiss = !expanded && shownAt != null
                && at.minusSeconds(quickDismissSeconds).isBefore(shownAt);
    }
}
