package com.sentinel.tracker.entity;

import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Represents a security vulnerability or warning detected by the security system
 * for a specific developer.
 *
 * Phase 01: Basic entity/database foundation only.
 * Lifecycle transitions will be implemented in Phase 02+.
 */
@Entity
@Table(
    name = "security_events",
    indexes = {
        @Index(name = "idx_se_developer_id",       columnList = "developer_id"),
        @Index(name = "idx_se_detected_at",        columnList = "detected_at"),
        @Index(name = "idx_se_vulnerability_type", columnList = "vulnerability_type"),
        @Index(name = "idx_se_severity",           columnList = "severity"),
        @Index(name = "idx_se_current_status",     columnList = "current_status")
    }
)
@EntityListeners(AuditingEntityListener.class)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ── Relationship ──────────────────────────────────────────────────────────

    /**
     * The developer who owns this security event.
     * Stored as a FK; the full Developer object is loaded lazily to avoid N+1.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "developer_id", nullable = false)
    private Developer developer;

    // ── Core event data ───────────────────────────────────────────────────────

    @Column(name = "vulnerability_type", nullable = false, length = 255)
    private String vulnerabilityType;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 50)
    private Severity severity;

    @Column(name = "file_name", nullable = false, length = 500)
    private String fileName;

    @Column(name = "line_number", nullable = false)
    private int lineNumber;

    @Column(name = "message", nullable = false, columnDefinition = "TEXT")
    private String message;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;

    /**
     * Current lifecycle status of the event.
     * Default is DETECTED when a new event is created.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "current_status", nullable = false, length = 50)
    @Builder.Default
    private SecurityEventStatus currentStatus = SecurityEventStatus.DETECTED;

    // ── Audit fields ──────────────────────────────────────────────────────────

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
