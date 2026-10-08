package com.sentinel.tracker.repository;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for {@link SecurityEvent} entities.
 */
@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    /**
     * Find all security events belonging to a specific developer.
     */
    List<SecurityEvent> findByDeveloperId(Long developerId);

    /**
     * Find all security events for a developer filtered by status.
     */
    List<SecurityEvent> findByDeveloperIdAndCurrentStatus(Long developerId, SecurityEventStatus status);

    /**
     * Find all security events for a developer filtered by severity.
     */
    List<SecurityEvent> findByDeveloperIdAndSeverity(Long developerId, Severity severity);

    /**
     * Find all security events with a given vulnerability type (e.g. "SQL_INJECTION").
     */
    List<SecurityEvent> findByVulnerabilityType(String vulnerabilityType);

    /**
     * Count how many events a developer currently has at each severity/status.
     * (More complex aggregations are reserved for Phase 02+.)
     */
    long countByDeveloperIdAndCurrentStatus(Long developerId, SecurityEventStatus status);
}
