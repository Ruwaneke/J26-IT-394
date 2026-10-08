package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.service.BehaviourAnalysisService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API for Developer Behaviour Analysis (Phase 03).
 */
@RestController
@RequestMapping("/api/developer-behaviour")
@RequiredArgsConstructor
public class DeveloperBehaviourController {

    private final BehaviourAnalysisService behaviourAnalysisService;

    @GetMapping("/{developerId}")
    public ResponseEntity<DeveloperBehaviourSummaryResponse> getDeveloperBehaviourSummary(@PathVariable Long developerId) {
        return ResponseEntity.ok(behaviourAnalysisService.getDeveloperBehaviourSummary(developerId));
    }
}
