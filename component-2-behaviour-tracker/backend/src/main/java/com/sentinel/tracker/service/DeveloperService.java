package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperRequest;
import com.sentinel.tracker.dto.DeveloperResponse;

import java.util.List;

/**
 * Service contract for Developer management operations.
 */
public interface DeveloperService {

    /**
     * Create a new developer. Throws {@link com.sentinel.tracker.exception.DuplicateResourceException}
     * if the identifier already exists.
     */
    DeveloperResponse createDeveloper(CreateDeveloperRequest request);

    /**
     * Retrieve a developer by their database ID.
     * Throws {@link com.sentinel.tracker.exception.ResourceNotFoundException} if not found.
     */
    DeveloperResponse getDeveloperById(Long id);

    /**
     * Retrieve all registered developers.
     */
    List<DeveloperResponse> getAllDevelopers();
}
