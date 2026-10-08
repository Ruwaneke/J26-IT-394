package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;

/**
 * Service for calculating and analyzing developer behaviour metrics.
 */
public interface BehaviourAnalysisService {

    /**
     * Calculates behaviour metrics and assigns a classification for the given developer.
     * Throws ResourceNotFoundException if the developer doesn't exist.
     */
    DeveloperBehaviourSummaryResponse getDeveloperBehaviourSummary(Long developerId);
}
