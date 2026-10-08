package com.sentinel.tracker.repository;

import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for {@link BehaviourLog} entities.
 */
@Repository
public interface BehaviourLogRepository extends JpaRepository<BehaviourLog, Long> {

    /**
     * Find all behaviour logs for a specific developer.
     */
    List<BehaviourLog> findByDeveloperId(Long developerId);

    /**
     * Find all behaviour logs associated with a specific security event.
     */
    List<BehaviourLog> findBySecurityEventId(Long securityEventId);

    /**
     * Find all behaviour logs for a developer filtered by action type.
     */
    List<BehaviourLog> findByDeveloperIdAndActionType(Long developerId, BehaviourAction actionType);
}
