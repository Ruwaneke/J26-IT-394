package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;

import java.util.List;

/**
 * Service contract for BehaviourLog management operations.
 *
 * Writes go through {@link DeveloperInteractionService}; this service keeps the
 * legacy behaviour-log read model and the deprecated create operation.
 */
public interface BehaviourLogService {

    /**
     * Record a new developer behaviour log entry.
     *
     * @deprecated Use {@link DeveloperInteractionService#createInteraction}. This method
     * delegates to it, so the security event status, lifecycle history and response time
     * are updated exactly as for a developer interaction.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if the
     * referenced developer or security event does not exist.
     */
    @Deprecated
    BehaviourLogResponse createBehaviourLog(CreateBehaviourLogRequest request);

    /**
     * Retrieve a behaviour log by its database ID.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if not found.
     */
    BehaviourLogResponse getBehaviourLogById(Long id);

    /**
     * Retrieve all behaviour logs for a specific developer.
     */
    List<BehaviourLogResponse> getBehaviourLogsByDeveloper(Long developerId);

    /**
     * Retrieve all behaviour logs.
     */
    List<BehaviourLogResponse> getAllBehaviourLogs();
}
