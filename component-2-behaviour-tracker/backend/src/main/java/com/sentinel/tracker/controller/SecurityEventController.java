package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.SecurityEventResponse;
import com.sentinel.tracker.service.SecurityEventService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for SecurityEvent resource management.
 *
 * Base path: /api/security-events
 */
@RestController
@RequestMapping("/api/security-events")
@RequiredArgsConstructor
@Tag(name = "Security Events", description = "Security event management endpoints")
public class SecurityEventController {

    private final SecurityEventService securityEventService;

    @PostMapping
    @Operation(summary = "Create a new security event")
    public ResponseEntity<SecurityEventResponse> createSecurityEvent(
            @Valid @RequestBody CreateSecurityEventRequest request) {

        SecurityEventResponse response = securityEventService.createSecurityEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a security event by ID")
    public ResponseEntity<SecurityEventResponse> getSecurityEventById(@PathVariable Long id) {
        return ResponseEntity.ok(securityEventService.getSecurityEventById(id));
    }

    @GetMapping
    @Operation(summary = "Get all security events")
    public ResponseEntity<List<SecurityEventResponse>> getAllSecurityEvents() {
        return ResponseEntity.ok(securityEventService.getAllSecurityEvents());
    }

    @GetMapping("/developer/{developerId}")
    @Operation(summary = "Get all security events for a specific developer")
    public ResponseEntity<List<SecurityEventResponse>> getSecurityEventsByDeveloper(
            @PathVariable Long developerId) {
        return ResponseEntity.ok(securityEventService.getSecurityEventsByDeveloper(developerId));
    }
}
