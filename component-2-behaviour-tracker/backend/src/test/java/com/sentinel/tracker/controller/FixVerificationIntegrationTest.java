package com.sentinel.tracker.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.FixVerificationStatus;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.service.FixVerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Claimed versus verified fixes on the real stack (TASKS P1-6), with C1's exact request bodies.
 *
 * <p>The verification bean is the real {@code ClaimOnlyFixVerificationService}, wrapped in a
 * spy. Tests that need a verification result stub it with a controlled mock result, standing
 * in for the C1 re-scan results that do not exist yet.
 */
class FixVerificationIntegrationTest extends ApiContractTestSupport {

    @SpyBean
    FixVerificationService fixVerificationService;

    @Test
    void fixFromC1_withoutAVerificationSource_shouldBeStoredAsClaimed() throws Exception {
        Long developerId = createDeveloper("fix-claimed");
        Long eventId = createEvent(developerId);

        sendAction(developerId, eventId, BehaviourAction.FIX)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.action").value("FIX"))
                .andExpect(jsonPath("$.fixVerification").value("CLAIMED"));

        assertThat(onlyLog(eventId).getFixVerification()).isEqualTo(FixVerificationStatus.CLAIMED);
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
        mockMvc.perform(get("/api/developer-behaviour/" + developerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fixedCount").value(1))
                .andExpect(jsonPath("$.fixRate").value(100.0))
                .andExpect(jsonPath("$.verifiedFixCount").value(0))
                .andExpect(jsonPath("$.verifiedFixRate").value(0.0));
    }

    @Test
    void fixFromC1_verifiedByTheMockSource_shouldBeStoredAsVerified() throws Exception {
        Long developerId = createDeveloper("fix-verified");
        Long eventId = createEvent(developerId);
        doReturn(FixVerificationStatus.VERIFIED).when(fixVerificationService).verifyFix(any(), any());

        sendAction(developerId, eventId, BehaviourAction.FIX)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fixVerification").value("VERIFIED"));

        assertThat(onlyLog(eventId).getFixVerification()).isEqualTo(FixVerificationStatus.VERIFIED);
        mockMvc.perform(get("/api/developer-interactions/security-event/" + eventId))
                .andExpect(jsonPath("$[0].fixVerification").value("VERIFIED"));
    }

    @Test
    void fixFromC1_stillVulnerable_shouldKeepTheClaimInTheLifecycleAndRecordTheResult() throws Exception {
        Long developerId = createDeveloper("fix-still-vulnerable");
        Long eventId = createEvent(developerId);
        doReturn(FixVerificationStatus.STILL_VULNERABLE).when(fixVerificationService).verifyFix(any(), any());

        sendAction(developerId, eventId, BehaviourAction.FIX)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fixVerification").value("STILL_VULNERABLE"));

        // C1 drops non-2xx responses, so the claim is accepted and the lifecycle unchanged
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId))
                .extracting(h -> h.getNewStatus())
                .containsExactly(SecurityEventStatus.DETECTED, SecurityEventStatus.FIXED);
        mockMvc.perform(get("/api/lifecycle-history/security-event/" + eventId + "/verify"))
                .andExpect(jsonPath("$.status").value("VALID"));
    }

    @Test
    void nonFixActions_shouldCarryNoFixVerification() throws Exception {
        Long developerId = createDeveloper("fix-other-actions");
        Long eventId = createEvent(developerId);

        for (BehaviourAction action : List.of(BehaviourAction.OPEN, BehaviourAction.IGNORE,
                BehaviourAction.DISMISS, BehaviourAction.REOPEN)) {
            JsonNode body = json(sendAction(developerId, eventId, action).andExpect(status().isCreated()));
            assertThat(body.path("fixVerification").isNull() || body.path("fixVerification").isMissingNode())
                    .as("fixVerification for %s", action).isTrue();
        }
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId))
                .allSatisfy(log -> assertThat(log.getFixVerification()).isNull());
    }

    @Test
    void summary_shouldSeparateClaimedFromVerifiedFixes() throws Exception {
        // 3 events: verified fix, claimed fix, no fix → fixRate 66.7, verifiedFixRate 33.3
        Long developerId = createDeveloper("fix-summary");
        Long verified = createEvent(developerId);
        Long claimed = createEvent(developerId);
        Long open = createEvent(developerId);
        doReturn(FixVerificationStatus.VERIFIED).when(fixVerificationService)
                .verifyFix(argThat(event -> event.getId().equals(verified)), any());

        sendAction(developerId, verified, BehaviourAction.FIX).andExpect(status().isCreated());
        sendAction(developerId, claimed, BehaviourAction.FIX).andExpect(status().isCreated());
        sendAction(developerId, open, BehaviourAction.OPEN).andExpect(status().isCreated());

        mockMvc.perform(get("/api/developer-behaviour/" + developerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fixedCount").value(2))
                .andExpect(jsonPath("$.fixRate").value(66.7))
                .andExpect(jsonPath("$.verifiedFixCount").value(1))
                .andExpect(jsonPath("$.verifiedFixRate").value(33.3));
    }

    @Test
    void legacyBehaviourLogFix_shouldAlsoBeRecordedAsClaimed() throws Exception {
        Long developerId = createDeveloper("fix-legacy");
        Long eventId = createEvent(developerId);

        postJson("/api/behaviour-logs", "{\"developerId\":" + developerId + ",\"securityEventId\":" + eventId
                + ",\"actionType\":\"FIX\"}")
                .andExpect(status().isCreated());

        assertThat(onlyLog(eventId).getFixVerification()).isEqualTo(FixVerificationStatus.CLAIMED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private BehaviourLog onlyLog(Long eventId) {
        List<BehaviourLog> logs = behaviourLogRepository.findBySecurityEventId(eventId);
        assertThat(logs).hasSize(1);
        return logs.get(0);
    }
}
