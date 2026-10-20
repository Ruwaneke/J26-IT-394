package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.HistoryVerificationResponse;
import com.sentinel.tracker.dto.LifecycleHistoryResponse;
import com.sentinel.tracker.service.VulnerabilityLifecycleHistoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping({"/api/lifecycle", "/api/lifecycle-history"})
@RequiredArgsConstructor
@Tag(name = "Lifecycle History", description = "Vulnerability lifecycle history endpoints")
public class LifecycleHistoryController {

    private final VulnerabilityLifecycleHistoryService lifecycleHistoryService;

    @GetMapping({"/security-event/{securityEventId}", "/{securityEventId}"})
    @Operation(summary = "Get the full lifecycle history for a security event")
    public ResponseEntity<List<LifecycleHistoryResponse>> getHistoryBySecurityEvent(
            @PathVariable Long securityEventId) {

        return ResponseEntity.ok(
                lifecycleHistoryService.getHistoryBySecurityEvent(securityEventId));
    }

    @GetMapping({"/security-event/{securityEventId}/verify", "/{securityEventId}/verify"})
    @Operation(summary = "Verify that a security event's lifecycle history has not been altered",
            description = "Recomputes the history's hash chain. VALID: intact. BROKEN: edited, deleted or "
                    + "reordered after it was written (see brokenAtEntry). UNCHAINED: some entries predate the "
                    + "hash chain and cannot be verified. Tamper-evident, not tamper-proof.")
    public ResponseEntity<HistoryVerificationResponse> verifyHistory(@PathVariable Long securityEventId) {
        return ResponseEntity.ok(lifecycleHistoryService.verifyHistory(securityEventId));
    }
}