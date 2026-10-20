package com.sentinel.tracker.controller;

import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Lifecycle regression tests on the real stack (TASKS P1-5): every status × action pair,
 * against the table in TECHNICAL_OVERVIEW §4.2–§4.4.
 *
 * <p>Each case drives a fresh event to the starting status with valid actions, then sends the
 * action under test and checks the outcome: a transition (201, one history row), a same-status
 * action (201, no history row, P1-1) or a rejected transition (409, nothing stored).
 */
class LifecycleTransitionIntegrationTest extends ApiContractTestSupport {

    private static final String DETECTED_AT = "2026-10-20T10:00:00";
    private static final String ACTION_AT = "2026-10-20T11:30:15.250";

    /** Valid action sequences that bring a new event to each status. */
    private static final Map<SecurityEventStatus, List<BehaviourAction>> PATH_TO = Map.of(
            SecurityEventStatus.DETECTED, List.of(),
            SecurityEventStatus.OPENED, List.of(BehaviourAction.OPEN),
            SecurityEventStatus.IGNORED, List.of(BehaviourAction.IGNORE),
            SecurityEventStatus.REOPENED, List.of(BehaviourAction.IGNORE, BehaviourAction.REOPEN),
            SecurityEventStatus.FIXED, List.of(BehaviourAction.FIX));

    /** Action → target status (TECHNICAL_OVERVIEW §4.2). */
    private static final Map<BehaviourAction, SecurityEventStatus> TARGET = Map.of(
            BehaviourAction.OPEN, SecurityEventStatus.OPENED,
            BehaviourAction.FIX, SecurityEventStatus.FIXED,
            BehaviourAction.IGNORE, SecurityEventStatus.IGNORED,
            BehaviourAction.DISMISS, SecurityEventStatus.IGNORED,
            BehaviourAction.REOPEN, SecurityEventStatus.REOPENED);

    enum Outcome { TRANSITION, SAME_STATUS, REJECTED }

    private Long developerId;

    @BeforeEach
    void setUp() {
        developerId = createDeveloper("transition-dev");
    }

    /** The expected outcome of every pair, written out from TECHNICAL_OVERVIEW §4.3 and §4.4. */
    static Stream<Arguments> everyStatusAndAction() {
        return Stream.of(
                Arguments.of(SecurityEventStatus.DETECTED, BehaviourAction.OPEN, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.DETECTED, BehaviourAction.FIX, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.DETECTED, BehaviourAction.IGNORE, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.DETECTED, BehaviourAction.DISMISS, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.DETECTED, BehaviourAction.REOPEN, Outcome.REJECTED),

                Arguments.of(SecurityEventStatus.OPENED, BehaviourAction.OPEN, Outcome.SAME_STATUS),
                Arguments.of(SecurityEventStatus.OPENED, BehaviourAction.FIX, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.OPENED, BehaviourAction.IGNORE, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.OPENED, BehaviourAction.DISMISS, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.OPENED, BehaviourAction.REOPEN, Outcome.REJECTED),

                Arguments.of(SecurityEventStatus.IGNORED, BehaviourAction.OPEN, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.IGNORED, BehaviourAction.FIX, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.IGNORED, BehaviourAction.IGNORE, Outcome.SAME_STATUS),
                Arguments.of(SecurityEventStatus.IGNORED, BehaviourAction.DISMISS, Outcome.SAME_STATUS),
                Arguments.of(SecurityEventStatus.IGNORED, BehaviourAction.REOPEN, Outcome.TRANSITION),

                Arguments.of(SecurityEventStatus.REOPENED, BehaviourAction.OPEN, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.REOPENED, BehaviourAction.FIX, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.REOPENED, BehaviourAction.IGNORE, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.REOPENED, BehaviourAction.DISMISS, Outcome.TRANSITION),
                Arguments.of(SecurityEventStatus.REOPENED, BehaviourAction.REOPEN, Outcome.SAME_STATUS),

                Arguments.of(SecurityEventStatus.FIXED, BehaviourAction.OPEN, Outcome.REJECTED),
                Arguments.of(SecurityEventStatus.FIXED, BehaviourAction.FIX, Outcome.SAME_STATUS),
                Arguments.of(SecurityEventStatus.FIXED, BehaviourAction.IGNORE, Outcome.REJECTED),
                Arguments.of(SecurityEventStatus.FIXED, BehaviourAction.DISMISS, Outcome.REJECTED),
                Arguments.of(SecurityEventStatus.FIXED, BehaviourAction.REOPEN, Outcome.TRANSITION));
    }

    @ParameterizedTest(name = "{0} + {1} -> {2}")
    @MethodSource("everyStatusAndAction")
    void action_fromStatus_shouldHaveTheDocumentedOutcome(SecurityEventStatus from, BehaviourAction action,
                                                          Outcome outcome) throws Exception {
        Long eventId = eventAt(from);
        long logsBefore = behaviourLogRepository.findBySecurityEventId(eventId).size();
        List<VulnerabilityLifecycleHistory> historyBefore = history(eventId);

        var result = sendAction(developerId, eventId, action, ACTION_AT);

        List<VulnerabilityLifecycleHistory> historyAfter = history(eventId);
        switch (outcome) {
            case TRANSITION -> {
                result.andExpect(status().isCreated());
                assertThat(currentStatus(eventId)).isEqualTo(TARGET.get(action));
                assertThat(historyAfter).hasSize(historyBefore.size() + 1);
                VulnerabilityLifecycleHistory added = historyAfter.get(historyAfter.size() - 1);
                assertThat(added.getPreviousStatus()).isEqualTo(from);
                assertThat(added.getNewStatus()).isEqualTo(TARGET.get(action));
                assertThat(added.getChangedAt()).isEqualTo(LocalDateTime.parse(ACTION_AT));
                assertThat(added.getChangedBy()).isEqualTo("transition-dev");
                assertThat(added.getPrevHash()).isEqualTo(historyBefore.get(historyBefore.size() - 1).getEntryHash());
                assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize((int) logsBefore + 1);
            }
            case SAME_STATUS -> {
                result.andExpect(status().isCreated()).andExpect(jsonPath("$.action").value(action.name()));
                assertThat(currentStatus(eventId)).isEqualTo(from);
                assertThat(historyAfter).hasSameSizeAs(historyBefore);
                assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize((int) logsBefore + 1);
            }
            case REJECTED -> {
                result.andExpect(status().isConflict())
                        .andExpect(apiError(409, "Conflict", "/api/developer-interactions"))
                        .andExpect(jsonPath("$.message", containsString(
                                "cannot move from " + from + " to " + TARGET.get(action))))
                        .andExpect(jsonPath("$.message", containsString("allowed next statuses")));
                assertThat(currentStatus(eventId)).isEqualTo(from);
                assertThat(historyAfter).extracting(VulnerabilityLifecycleHistory::getId)
                        .containsExactlyElementsOf(historyBefore.stream().map(VulnerabilityLifecycleHistory::getId).toList());
                assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize((int) logsBefore);
            }
        }
        expectChainValid(eventId);
    }

    @Test
    void fullJourney_shouldRecordEveryTransitionWithItsActorAndTime() throws Exception {
        Long eventId = createEventAt(DETECTED_AT);
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:01:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:01:30").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.IGNORE, "2026-10-20T10:02:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.DISMISS, "2026-10-20T10:02:30").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:03:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.FIX, "2026-10-20T10:04:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:05:00").andExpect(status().isConflict());
        sendAction(developerId, eventId, BehaviourAction.REOPEN, "2026-10-20T10:06:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.FIX, "2026-10-20T10:07:00").andExpect(status().isCreated());

        List<VulnerabilityLifecycleHistory> history = history(eventId);
        assertThat(history).extracting(h -> h.getPreviousStatus() + ">" + h.getNewStatus()).containsExactly(
                "null>DETECTED", "DETECTED>OPENED", "OPENED>IGNORED", "IGNORED>OPENED",
                "OPENED>FIXED", "FIXED>REOPENED", "REOPENED>FIXED");
        assertThat(history).extracting(VulnerabilityLifecycleHistory::getChangedAt).containsExactly(
                LocalDateTime.parse("2026-10-20T10:00:00"), LocalDateTime.parse("2026-10-20T10:01:00"),
                LocalDateTime.parse("2026-10-20T10:02:00"), LocalDateTime.parse("2026-10-20T10:03:00"),
                LocalDateTime.parse("2026-10-20T10:04:00"), LocalDateTime.parse("2026-10-20T10:06:00"),
                LocalDateTime.parse("2026-10-20T10:07:00"));
        assertThat(history).extracting(VulnerabilityLifecycleHistory::getChangedBy).containsExactly(
                "SYSTEM", "transition-dev", "transition-dev", "transition-dev",
                "transition-dev", "transition-dev", "transition-dev");
        // 8 accepted actions logged (the 409 is not), including the same-status OPEN and DISMISS
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(8);
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
        expectChainValid(eventId);
    }

    @Test
    void repeatedOpen_p1_1_shouldStayAcceptedEveryTime() throws Exception {
        Long eventId = createEventAt(DETECTED_AT);
        for (int i = 0; i < 5; i++) {
            sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());
        }
        assertThat(history(eventId)).hasSize(2);
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(5);
    }

    @Test
    void legacyBehaviourLogEndpoint_shouldFollowTheSameLifecycleRules() throws Exception {
        Long eventId = createEventAt(DETECTED_AT);

        postJson("/api/behaviour-logs", "{\"developerId\":" + developerId + ",\"securityEventId\":" + eventId
                + ",\"actionType\":\"FIX\",\"timestamp\":\"2026-10-20T10:09:00\"}")
                .andExpect(status().isCreated())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header()
                        .string("Deprecation", "true"));
        postJson("/api/behaviour-logs", "{\"developerId\":" + developerId + ",\"securityEventId\":" + eventId
                + ",\"action\":\"OPEN\"}")
                .andExpect(status().isConflict());

        assertThat(history(eventId)).extracting(VulnerabilityLifecycleHistory::getNewStatus)
                .containsExactly(SecurityEventStatus.DETECTED, SecurityEventStatus.FIXED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Long createEventAt(String detectedAt) throws Exception {
        return createEvent(String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"" + detectedAt + "\"}"));
    }

    private Long eventAt(SecurityEventStatus target) throws Exception {
        Long eventId = createEventAt(DETECTED_AT);
        int minute = 1;
        for (BehaviourAction step : PATH_TO.get(target)) {
            sendAction(developerId, eventId, step, String.format("2026-10-20T10:%02d:00", minute++))
                    .andExpect(status().isCreated());
        }
        assertThat(currentStatus(eventId)).isEqualTo(target);
        return eventId;
    }

    private List<VulnerabilityLifecycleHistory> history(Long eventId) {
        return lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId);
    }

    private void expectChainValid(Long eventId) throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALID"));
    }
}
