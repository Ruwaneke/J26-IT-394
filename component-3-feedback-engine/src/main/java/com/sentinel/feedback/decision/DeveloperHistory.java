package com.sentinel.feedback.decision;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Behaviour history for one developer and the CWE being decided, as supplied by
 * Component 2. {@code lastSimilarDaysAgo} is null when there is no earlier similar event.
 */
public record DeveloperHistory(
        @NotBlank String devHash,
        @Min(0) int repeats30d,
        @Min(0) int ignored30d,
        @Min(0) int fixed30d,
        @Min(0) int reopened30d,
        @Min(0) Integer lastSimilarDaysAgo
) {
}
