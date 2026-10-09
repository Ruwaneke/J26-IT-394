package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.Severity;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Request DTO for creating a new SecurityEvent.
 */
@Data
public class CreateSecurityEventRequest {

    @NotNull(message = "developerId must not be null")
    private Long developerId;

    @NotBlank(message = "vulnerabilityType must not be blank")
    @Size(max = 255, message = "vulnerabilityType must be at most 255 characters")
    private String vulnerabilityType;

    @NotNull(message = "severity must not be null")
    private Severity severity;

    @NotBlank(message = "fileName must not be blank")
    @Size(max = 500, message = "fileName must be at most 500 characters")
    private String fileName;

    /**
     * Boxed so that a missing value is rejected instead of silently defaulting to 0.
     */
    @NotNull(message = "lineNumber must not be null")
    @Min(value = 0, message = "lineNumber must be zero or positive")
    private Integer lineNumber;

    @NotBlank(message = "message must not be blank")
    private String message;

    /**
     * When the event was detected. Defaults to now if not provided.
     */
    private LocalDateTime detectedAt;
}
