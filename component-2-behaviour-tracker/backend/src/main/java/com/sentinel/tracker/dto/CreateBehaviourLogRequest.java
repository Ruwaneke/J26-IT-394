package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.BehaviourAction;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Request DTO for creating a new BehaviourLog entry.
 */
@Data
public class CreateBehaviourLogRequest {

    @NotNull(message = "developerId must not be null")
    private Long developerId;

    /**
     * Optional — a log may not always be associated with a specific security event.
     */
    private Long securityEventId;

    @NotNull(message = "actionType must not be null")
    private BehaviourAction actionType;

    /**
     * Timestamp of the action. Defaults to now if not provided.
     */
    private LocalDateTime timestamp;

    /**
     * Optional context or metadata string (e.g. JSON payload from VS Code extension).
     */
    private String contextMetadata;
}
