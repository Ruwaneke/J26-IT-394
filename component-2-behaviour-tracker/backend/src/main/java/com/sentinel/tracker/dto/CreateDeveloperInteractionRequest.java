package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.BehaviourAction;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
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

    @Size(max = 255, message = "sessionId must be at most 255 characters")
    private String sessionId;

    @Size(max = 255, message = "source must be at most 255 characters")
    private String source;

    /**
     * Free-form metadata about the interaction.
     */
    private String metadata;
}
