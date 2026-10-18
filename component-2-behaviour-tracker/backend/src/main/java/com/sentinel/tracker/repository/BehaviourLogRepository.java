package com.sentinel.tracker.repository;

import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link BehaviourLog} entities.
 */
@Repository
public interface BehaviourLogRepository extends JpaRepository<BehaviourLog, Long> {

    /**
     * Override findById to eagerly fetch developer and securityEvent.
     */
    @Override
    @EntityGraph(attributePaths = {"developer", "securityEvent"})
    Optional<BehaviourLog> findById(Long id);

    /**
     * Find all behaviour logs for a specific developer.
     */
    @EntityGraph(attributePaths = {"developer", "securityEvent"})
    List<BehaviourLog> findByDeveloperId(Long developerId);

    /**
     * Find all behaviour logs associated with a specific security event.
     */
    @EntityGraph(attributePaths = {"developer", "securityEvent"})
    List<BehaviourLog> findBySecurityEventId(Long securityEventId);

    /**
     * Find all behaviour logs for a developer filtered by action type.
     */
    @EntityGraph(attributePaths = {"developer", "securityEvent"})
    List<BehaviourLog> findByDeveloperIdAndActionType(Long developerId, BehaviourAction actionType);
}
