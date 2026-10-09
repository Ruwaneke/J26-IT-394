package com.sentinel.tracker.dto;

import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for BehaviourLog resources.
 */
@Data
@Builder
public class BehaviourLogResponse {

    private Long id;
    private Long developerId;
    private Long securityEventId;
    private BehaviourAction actionType;
    private LocalDateTime timestamp;
    private String contextMetadata;
    private LocalDateTime createdAt;

    /**
     * Factory method: converts a BehaviourLog entity to a BehaviourLogResponse DTO.
     */
    public static BehaviourLogResponse from(BehaviourLog log) {
        return BehaviourLogResponse.builder()
                .id(log.getId())
                .developerId(log.getDeveloper().getId())
                .securityEventId(log.getSecurityEvent() != null ? log.getSecurityEvent().getId() : null)
                .actionType(log.getActionType())
                .timestamp(log.getTimestamp())
                .contextMetadata(log.getContextMetadata())
                .createdAt(log.getCreatedAt())
                .build();
    }

    /**
     * Factory method: maps a developer interaction (same underlying BehaviourLog row)
     * to the legacy behaviour-log representation.
     */
    public static BehaviourLogResponse from(DeveloperInteractionResponse interaction) {
        return BehaviourLogResponse.builder()
                .id(interaction.getId())
                .developerId(interaction.getDeveloperId())
                .securityEventId(interaction.getSecurityEventId())
                .actionType(interaction.getAction())
                .timestamp(interaction.getActionTimestamp())
                .contextMetadata(interaction.getMetadata())
                .createdAt(interaction.getCreatedAt())
                .build();
    }
}
