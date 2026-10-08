package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.service.BehaviourLogService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for BehaviourLog resource management.
 *
 * Base path: /api/behaviour-logs
 */
@RestController
@RequestMapping("/api/behaviour-logs")
@RequiredArgsConstructor
@Tag(name = "Behaviour Logs", description = "Developer behaviour log management endpoints")
public class BehaviourLogController {

    private final BehaviourLogService behaviourLogService;

    @PostMapping
    @Operation(summary = "Create a new behaviour log entry")
    public ResponseEntity<BehaviourLogResponse> createBehaviourLog(
            @Valid @RequestBody CreateBehaviourLogRequest request) {

        BehaviourLogResponse response = behaviourLogService.createBehaviourLog(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a behaviour log by ID")
    public ResponseEntity<BehaviourLogResponse> getBehaviourLogById(@PathVariable Long id) {
        return ResponseEntity.ok(behaviourLogService.getBehaviourLogById(id));
    }

    @GetMapping
    @Operation(summary = "Get all behaviour logs")
    public ResponseEntity<List<BehaviourLogResponse>> getAllBehaviourLogs() {
        return ResponseEntity.ok(behaviourLogService.getAllBehaviourLogs());
    }

    @GetMapping("/developer/{developerId}")
    @Operation(summary = "Get all behaviour logs for a specific developer")
    public ResponseEntity<List<BehaviourLogResponse>> getBehaviourLogsByDeveloper(
            @PathVariable Long developerId) {
        return ResponseEntity.ok(behaviourLogService.getBehaviourLogsByDeveloper(developerId));
    }
}
