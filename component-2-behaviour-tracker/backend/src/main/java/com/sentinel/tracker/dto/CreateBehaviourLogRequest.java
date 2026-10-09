package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.BehaviourAction;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Request DTO for creating a new BehaviourLog entry.
 *
 * @deprecated Used only by the deprecated {@code POST /api/behaviour-logs}.
 * Use {@link CreateDeveloperInteractionRequest} with {@code POST /api/developer-interactions}.
 */
@Deprecated
@Data
public class CreateBehaviourLogRequest {

    @NotNull(message = "developerId must not be null")
    private Long developerId;

    /**
     * Required – every action is applied to a security event's lifecycle.
     */
    @NotNull(message = "securityEventId must not be null")
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
