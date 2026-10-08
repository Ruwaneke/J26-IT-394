package com.sentinel.tracker.dto;

import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for a developer interaction in Phase 03.
 */
@Data
@Builder
public class DeveloperInteractionResponse {
    
    private Long id;
    private Long securityEventId;
    private Long developerId;
    private BehaviourAction action;
    private LocalDateTime actionTimestamp;
    private Long timeSinceDetectionSeconds;
    private String sessionId;
    private String source;
    private String metadata;
    private LocalDateTime createdAt;

    /**
     * Factory method to convert an extended BehaviourLog entity to a DeveloperInteractionResponse DTO.
     */
    public static DeveloperInteractionResponse from(BehaviourLog log) {
        return DeveloperInteractionResponse.builder()
                .id(log.getId())
                .securityEventId(log.getSecurityEvent() != null ? log.getSecurityEvent().getId() : null)
                .developerId(log.getDeveloper().getId())
                .action(log.getActionType())
                .actionTimestamp(log.getTimestamp())
                .timeSinceDetectionSeconds(log.getTimeSinceDetectionSeconds())
                .sessionId(log.getSessionId())
                .source(log.getSource())
                .metadata(log.getContextMetadata())
                .createdAt(log.getCreatedAt())
                .build();
    }
}
