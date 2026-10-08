package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.service.BehaviourLogService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST API for Developer Interactions (Phase 03).
 */
@RestController
@RequestMapping("/api/developer-interactions")
@RequiredArgsConstructor
public class DeveloperInteractionController {

    private final BehaviourLogService behaviourLogService;

    @PostMapping
    public ResponseEntity<DeveloperInteractionResponse> createInteraction(@Valid @RequestBody CreateDeveloperInteractionRequest request) {
        DeveloperInteractionResponse response = behaviourLogService.createInteraction(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping("/{id}")
    public ResponseEntity<DeveloperInteractionResponse> getInteractionById(@PathVariable Long id) {
        return ResponseEntity.ok(behaviourLogService.getInteractionById(id));
    }

    @GetMapping
    public ResponseEntity<List<DeveloperInteractionResponse>> getAllInteractions() {
        return ResponseEntity.ok(behaviourLogService.getAllInteractions());
    }

    @GetMapping("/developer/{developerId}")
    public ResponseEntity<List<DeveloperInteractionResponse>> getInteractionsByDeveloper(@PathVariable Long developerId) {
        return ResponseEntity.ok(behaviourLogService.getInteractionsByDeveloper(developerId));
    }

    @GetMapping("/security-event/{securityEventId}")
    public ResponseEntity<List<DeveloperInteractionResponse>> getInteractionsBySecurityEvent(@PathVariable Long securityEventId) {
        return ResponseEntity.ok(behaviourLogService.getInteractionsBySecurityEvent(securityEventId));
    }
}
