package com.sentinel.tracker.entity;

import com.sentinel.tracker.enums.BehaviourAction;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Records a developer's action in response to a security event.
 *
 * Phase 01: Entity and database foundation only.
 * Actual event capture from VS Code will be integrated in Phase 02+.
 */
@Entity
@Table(
    name = "behaviour_logs",
    indexes = {
        @Index(name = "idx_bl_developer_id",     columnList = "developer_id"),
        @Index(name = "idx_bl_security_event_id", columnList = "security_event_id"),
        @Index(name = "idx_bl_timestamp",         columnList = "timestamp"),
        @Index(name = "idx_bl_action_type",       columnList = "action_type")
    }
)
@EntityListeners(AuditingEntityListener.class)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BehaviourLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ── Relationships ─────────────────────────────────────────────────────────

    /**
     * The developer who performed the action.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "developer_id", nullable = false)
    private Developer developer;

    /**
     * The security event this action is related to (optional – a log may be
     * general and not tied to a specific event in future phases).
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "security_event_id")
    private SecurityEvent securityEvent;

    // ── Action data ───────────────────────────────────────────────────────────

    @Enumerated(EnumType.STRING)
    @Column(name = "action_type", nullable = false, length = 50)
    private BehaviourAction actionType;

    /**
     * When the action occurred (set by the caller; may differ from createdAt
     * if events are ingested asynchronously in later phases).
     */
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    /**
     * Free-form JSON or plain-text context/metadata about the action.
     * For example: IDE context, file diff, cursor position.
     * Reserved for Phase 02+ enrichment.
     */
    @Column(name = "context_metadata", columnDefinition = "TEXT")
    private String contextMetadata;

    // ── Phase 03 Extensions ───────────────────────────────────────────────────

    @Column(name = "time_since_detection_seconds")
    private Long timeSinceDetectionSeconds;

    @Column(name = "session_id", length = 255)
    private String sessionId;

    @Column(name = "source", length = 255)
    private String source;

    // ── Audit ─────────────────────────────────────────────────────────────────

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
}
