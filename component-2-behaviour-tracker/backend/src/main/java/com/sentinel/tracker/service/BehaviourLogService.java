package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;

import java.util.List;

/**
 * Service contract for BehaviourLog management operations.
 */
public interface BehaviourLogService {

    /**
     * Record a new developer behaviour log entry.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if the
     * referenced developer or security event does not exist.
     */
    BehaviourLogResponse createBehaviourLog(CreateBehaviourLogRequest request);

    /**
     * Phase 03: Create a developer interaction tracking log, which also updates
     * the SecurityEvent lifecycle status automatically.
     */
    DeveloperInteractionResponse createInteraction(CreateDeveloperInteractionRequest request);

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

    // ── Phase 03 Interaction Retrieval ────────────────────────────────────────

    DeveloperInteractionResponse getInteractionById(Long id);

    List<DeveloperInteractionResponse> getAllInteractions();

    List<DeveloperInteractionResponse> getInteractionsByDeveloper(Long developerId);

    List<DeveloperInteractionResponse> getInteractionsBySecurityEvent(Long securityEventId);
}
