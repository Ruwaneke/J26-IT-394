package com.sentinel.feedback.decision;

import com.sentinel.feedback.model.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * A finding from Component 1. The snippet is kept for the later LLM stage; the file is
 * used by the cooldown rule.
 */
public record FeedbackEvent(
        @NotBlank String eventId,
        @NotBlank String cwe,
        @NotNull Severity severity,
        String language,
        int line,
        String snippet,
        String file
) {
}
