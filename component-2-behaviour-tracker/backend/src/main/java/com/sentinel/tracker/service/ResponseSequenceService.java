package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse;

/**
 * Behaviour Sequence Intelligence: recurring developer response sequences across security
 * events (TASKS P2-10, TECHNICAL_OVERVIEW §7.4).
 */
public interface ResponseSequenceService {

    /**
     * Response-sequence patterns and action transitions for the given developer.
     * Throws ResourceNotFoundException if the developer doesn't exist.
     */
    ResponseSequenceAnalysisResponse getResponseSequences(Long developerId);
}
