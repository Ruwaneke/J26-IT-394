package com.sentinel.tracker.dto;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for SecurityEvent resources.
 */
@Data
@Builder
public class SecurityEventResponse {

    private Long id;
    private Long developerId;
    private String vulnerabilityType;
    private Severity severity;
    private String fileName;
    private int lineNumber;
    private String message;
    private LocalDateTime detectedAt;
    private SecurityEventStatus currentStatus;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /**
     * Factory method: converts a SecurityEvent entity to a SecurityEventResponse DTO.
     */
    public static SecurityEventResponse from(SecurityEvent event) {
        return SecurityEventResponse.builder()
                .id(event.getId())
                .developerId(event.getDeveloper().getId())
                .vulnerabilityType(event.getVulnerabilityType())
                .severity(event.getSeverity())
                .fileName(event.getFileName())
                .lineNumber(event.getLineNumber())
                .message(event.getMessage())
                .detectedAt(event.getDetectedAt())
                .currentStatus(event.getCurrentStatus())
                .createdAt(event.getCreatedAt())
                .updatedAt(event.getUpdatedAt())
                .build();
    }
}
