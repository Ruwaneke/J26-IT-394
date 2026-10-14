package com.sentinel.feedback.model;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record SecurityEvent(
        @NotBlank String eventId,
        @NotBlank String developerId,
        @NotBlank String sessionId,
        @NotNull VulnerabilityType vulnerabilityType,
        @NotNull Severity severity,
        @DecimalMin("0.0") @DecimalMax("1.0") double confidence,
        @NotBlank String fileName,
        int lineNumber,
        @NotNull Instant detectedAt
) {
}
