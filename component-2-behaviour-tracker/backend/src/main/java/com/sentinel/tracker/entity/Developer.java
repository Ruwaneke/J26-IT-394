package com.sentinel.tracker.entity;

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
 * Represents a developer being tracked in the system.
 *
 * Each developer is uniquely identified by a developerIdentifier (e.g., GitHub username,
 * employee ID, or email). Timestamps are managed automatically by JPA auditing.
 */
@Entity
@Table(
    name = "developers",
    indexes = {
        @Index(name = "idx_developer_identifier", columnList = "developer_identifier")
    }
)
@EntityListeners(AuditingEntityListener.class)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Developer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique identifier for the developer (e.g., GitHub username, employee ID).
     * Must be unique across all developers.
     */
    @Column(name = "developer_identifier", nullable = false, unique = true, length = 255)
    private String developerIdentifier;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
