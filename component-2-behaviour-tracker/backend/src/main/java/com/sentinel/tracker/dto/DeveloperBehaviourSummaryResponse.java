package com.sentinel.tracker.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Response DTO for Developer Behaviour Summary in Phase 03.
 */
@Data
@Builder
public class DeveloperBehaviourSummaryResponse {
    
    private Long developerId;
    private Long totalSecurityEvents;
    
    // Interaction counts (distinct security events that received the action)
    private Long openedCount;
    private Long fixedCount;
    private Long ignoredCount;
    private Long dismissedCount;
    private Long reopenedCount;
    
    // Derived rates (percentages 0.0 - 100.0)
    private Double fixRate;
    private Double ignoreRate;
    private Double reopenRate;
    /** Null when the developer has no HIGH/CRITICAL security events (not applicable). */
    private Double highSeverityFixRate;
    
    private Double averageResponseTimeSeconds;
    private Long repeatedVulnerabilityCount;
    
    // Explainable behaviour classification
    private String behaviourClassification;
}
