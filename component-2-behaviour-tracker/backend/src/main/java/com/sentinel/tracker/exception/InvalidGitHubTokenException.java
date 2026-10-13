package com.sentinel.tracker.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when GitHub rejects the access token supplied by the client
 * (missing, expired or revoked).
 * Maps to HTTP 401 Unauthorized.
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidGitHubTokenException extends RuntimeException {

    public InvalidGitHubTokenException() {
        super("Invalid or expired GitHub access token");
    }
}
