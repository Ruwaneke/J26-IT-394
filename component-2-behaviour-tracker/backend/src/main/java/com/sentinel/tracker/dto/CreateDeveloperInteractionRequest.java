package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.BehaviourAction;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Request DTO for creating a new developer interaction in Phase 03.
 */
@Data
public class CreateDeveloperInteractionRequest {

    @NotNull(message = "securityEventId must not be null")
    private Long securityEventId;

    @NotNull(message = "developerId must not be null")
    private Long developerId;

    @NotNull(message = "action must not be null")
    private BehaviourAction action;

    /**
     * Optional timestamp when the interaction occurred. Defaults to now.
     */
    private LocalDateTime actionTimestamp;

    private String sessionId;

    private String source;

    /**
     * Free-form metadata about the interaction.
     */
    private String metadata;
}
