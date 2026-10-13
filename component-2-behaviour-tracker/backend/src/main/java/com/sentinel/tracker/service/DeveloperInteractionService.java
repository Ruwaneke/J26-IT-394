package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;

import java.util.List;

/**
 * Service contract for developer interaction operations (Phase 03).
 *
 * <p>A developer interaction records an action a developer took on a security event
 * (e.g. OPEN, FIX, IGNORE). Creating an interaction also:
 * <ul>
 *   <li>Validates that the developer owns the targeted security event.</li>
 *   <li>Validates that the action produces a valid lifecycle transition.</li>
 *   <li>Updates the security event's {@code currentStatus}.</li>
 *   <li>Appends a {@code VulnerabilityLifecycleHistory} entry.</li>
 *   <li>Computes and stores {@code timeSinceDetectionSeconds}.</li>
 * </ul>
 */
public interface DeveloperInteractionService {

    /**
     * Record a new developer interaction against a security event.
     *
     * @throws com.sentinel.tracker.exception.ResourceNotFoundException     if the developer or
     *                                                                       security event does not exist.
     * @throws com.sentinel.tracker.exception.AccessDeniedException          if the developer does not own
     *                                                                       the security event.
     * @throws com.sentinel.tracker.exception.InvalidStatusTransitionException if the action would move
     *                                                                       the security event to a status
     *                                                                       that is not allowed from its
     *                                                                       current status.
     */
    DeveloperInteractionResponse createInteraction(CreateDeveloperInteractionRequest request);

    /**
     * Retrieve a single interaction by its database ID.
     *
     * @throws com.sentinel.tracker.exception.ResourceNotFoundException if not found.
     */
    DeveloperInteractionResponse getInteractionById(Long id);

    /**
     * Retrieve all interactions across all developers.
     */
    List<DeveloperInteractionResponse> getAllInteractions();

    /**
     * Retrieve all interactions performed by a specific developer.
     *
     * @throws com.sentinel.tracker.exception.ResourceNotFoundException if the developer does not exist.
     */
    List<DeveloperInteractionResponse> getInteractionsByDeveloper(Long developerId);

    /**
     * Retrieve all interactions associated with a specific security event.
     *
     * @throws com.sentinel.tracker.exception.ResourceNotFoundException if the security event does not exist.
     */
    List<DeveloperInteractionResponse> getInteractionsBySecurityEvent(Long securityEventId);
}
