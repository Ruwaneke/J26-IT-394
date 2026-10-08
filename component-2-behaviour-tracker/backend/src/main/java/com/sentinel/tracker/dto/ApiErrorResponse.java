package com.sentinel.tracker.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Standard API error response body returned by {@link com.sentinel.tracker.exception.GlobalExceptionHandler}.
 */
@Data
@Builder
public class ApiErrorResponse {

    private LocalDateTime timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
}
