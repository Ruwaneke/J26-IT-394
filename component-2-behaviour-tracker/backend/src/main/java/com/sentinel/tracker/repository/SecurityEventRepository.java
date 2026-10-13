package com.sentinel.tracker.repository;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link SecurityEvent} entities.
 */
@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    /**
     * Find a security event and lock its row until the current transaction ends, so that
     * concurrent actions on the same event are validated and applied one after another.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select e from SecurityEvent e where e.id = :id")
    Optional<SecurityEvent> findByIdForUpdate(@Param("id") Long id);

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
