package com.sentinel.tracker.dto;

import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.SecurityEventStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for VulnerabilityLifecycleHistory resources.
 */
@Data
@Builder
public class LifecycleHistoryResponse {

    private Long id;
    private Long securityEventId;
    private SecurityEventStatus previousStatus;
    private SecurityEventStatus newStatus;
    private LocalDateTime changedAt;
    private String changedBy;
    private LocalDateTime createdAt;

    /**
     * Factory method: converts a VulnerabilityLifecycleHistory entity to a DTO.
     */
    public static LifecycleHistoryResponse from(VulnerabilityLifecycleHistory history) {
        return LifecycleHistoryResponse.builder()
                .id(history.getId())
                .securityEventId(history.getSecurityEvent().getId())
                .previousStatus(history.getPreviousStatus())
                .newStatus(history.getNewStatus())
                .changedAt(history.getChangedAt())
                .changedBy(history.getChangedBy())
                .createdAt(history.getCreatedAt())
                .build();
    }
}
