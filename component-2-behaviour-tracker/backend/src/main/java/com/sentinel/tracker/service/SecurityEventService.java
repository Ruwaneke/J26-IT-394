package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.SecurityEventResponse;

import java.util.List;

/**
 * Service contract for SecurityEvent management operations.
 */
public interface SecurityEventService {

    /**
     * Create and persist a new security event linked to the given developer.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if the developer
     * referenced in the request does not exist.
     */
    SecurityEventResponse createSecurityEvent(CreateSecurityEventRequest request);

    /**
     * Retrieve a security event by its database ID.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if not found.
     */
    SecurityEventResponse getSecurityEventById(Long id);

    /**
     * Retrieve all security events.
     */
    List<SecurityEventResponse> getAllSecurityEvents();

    /**
     * Retrieve all security events belonging to a specific developer.
     */
    List<SecurityEventResponse> getSecurityEventsByDeveloper(Long developerId);
}
