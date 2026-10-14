package com.sentinel.feedback.model;

public record FeedbackResponse(
        String eventId,
        int score,
        Severity severity,
        String message
) {
}
