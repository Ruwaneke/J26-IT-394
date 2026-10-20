package com.sentinel.tracker.controller;

import com.sentinel.tracker.enums.BehaviourAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract tests for the lifecycle-history reads (all four path forms) and
 * {@code GET /api/developer-behaviour/{developerId}} on the real stack (TASKS P1-5).
 */
class LifecycleAndBehaviourApiContractTest extends ApiContractTestSupport {

    private static final String[] HISTORY_PATHS = {
            "/api/lifecycle-history/security-event/{id}",
            "/api/lifecycle/security-event/{id}",
            "/api/lifecycle-history/{id}",
            "/api/lifecycle/{id}"
    };

    private Long developerId;
    private Long eventId;

    @BeforeEach
    void setUp() throws Exception {
        developerId = createDeveloper("lifecycle-contract-dev");
        eventId = createEvent(String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"2026-10-20T10:00:00\"}"));
    }

    // ── Lifecycle history ─────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void history_everyPathForm_shouldReturn200WithTheSameEntries(int pathIndex) throws Exception {
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:01:00");
        sendAction(developerId, eventId, BehaviourAction.FIX, "2026-10-20T10:05:00");

        mockMvc.perform(get(HISTORY_PATHS[pathIndex], eventId))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[0].securityEventId").value(eventId))
                .andExpect(jsonPath("$[0].previousStatus").value(nullValue()))
                .andExpect(jsonPath("$[0].newStatus").value("DETECTED"))
                .andExpect(jsonPath("$[0].changedBy").value("SYSTEM"))
                .andExpect(jsonPath("$[0].changedAt").value("2026-10-20T10:00:00"))
                .andExpect(jsonPath("$[1].previousStatus").value("DETECTED"))
                .andExpect(jsonPath("$[1].newStatus").value("OPENED"))
                .andExpect(jsonPath("$[1].changedBy").value("lifecycle-contract-dev"))
                .andExpect(jsonPath("$[1].changedAt").value("2026-10-20T10:01:00"))
                .andExpect(jsonPath("$[2].previousStatus").value("OPENED"))
                .andExpect(jsonPath("$[2].newStatus").value("FIXED"))
                .andExpect(jsonPath("$[2].changedAt").value("2026-10-20T10:05:00"))
                .andExpect(jsonPath("$[2].entryHash").isString())
                .andExpect(jsonPath("$[2].id").isNumber())
                .andExpect(jsonPath("$[2].createdAt").isString());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void history_unknownEvent_shouldReturn404OnEveryPathForm(int pathIndex) throws Exception {
        String path = HISTORY_PATHS[pathIndex].replace("{id}", "616161");
        mockMvc.perform(get(path))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", path))
                .andExpect(jsonPath("$.message").value("Security event not found with id: '616161'"));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3})
    void verify_everyPathForm_shouldReturn200(int pathIndex) throws Exception {
        mockMvc.perform(get(HISTORY_PATHS[pathIndex] + "/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.securityEventId").value(eventId))
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.entryCount").value(1))
                .andExpect(jsonPath("$.unchainedEntryCount").value(0))
                .andExpect(jsonPath("$.brokenAtEntry").value(nullValue()))
                .andExpect(jsonPath("$.brokenAtHistoryId").value(nullValue()))
                .andExpect(jsonPath("$.reason").value(nullValue()))
                .andExpect(jsonPath("$.verifiedAt").isString());
    }

    @Test
    void history_isOrderedByChangedAtOldestFirst() throws Exception {
        // Client timestamps need not increase: the action sent second happened earlier
        sendAction(developerId, eventId, BehaviourAction.IGNORE, "2026-10-20T12:00:00");
        sendAction(developerId, eventId, BehaviourAction.REOPEN, "2026-10-20T11:00:00");

        mockMvc.perform(get(HISTORY_PATHS[0], eventId))
                .andExpect(jsonPath("$[0].newStatus").value("DETECTED"))
                .andExpect(jsonPath("$[1].newStatus").value("REOPENED"))
                .andExpect(jsonPath("$[2].newStatus").value("IGNORED"));
    }

    // ── Behaviour summary ─────────────────────────────────────────────────────

    @Test
    void behaviourSummary_shouldReturnHandCalculatedValues() throws Exception {
        // 3 events: A fixed (HIGH), B ignored then dismissed (HIGH), C opened twice (LOW)
        Long eventB = createEvent(String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"2026-10-20T10:00:00\"}"));
        Long eventC = createEvent(String.format(C1_EVENT_BODY, developerId).replace("\"HIGH\"", "\"LOW\"")
                .replace("}", ",\"detectedAt\":\"2026-10-20T10:00:00\"}"));
        sendAction(developerId, eventId, BehaviourAction.FIX, "2026-10-20T10:01:00");    // 60 s
        sendAction(developerId, eventB, BehaviourAction.IGNORE, "2026-10-20T10:02:00");  // 120 s
        sendAction(developerId, eventB, BehaviourAction.DISMISS, "2026-10-20T10:03:00"); // 180 s
        sendAction(developerId, eventC, BehaviourAction.OPEN, "2026-10-20T10:04:00");    // 240 s
        sendAction(developerId, eventC, BehaviourAction.OPEN, "2026-10-20T10:05:00");    // 300 s

        mockMvc.perform(get("/api/developer-behaviour/{id}", developerId))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.developerId").value(developerId))
                .andExpect(jsonPath("$.totalSecurityEvents").value(3))
                .andExpect(jsonPath("$.openedCount").value(1))
                .andExpect(jsonPath("$.fixedCount").value(1))
                .andExpect(jsonPath("$.ignoredCount").value(1))
                .andExpect(jsonPath("$.dismissedCount").value(1))
                .andExpect(jsonPath("$.reopenedCount").value(0))
                .andExpect(jsonPath("$.fixRate").value(33.3))
                .andExpect(jsonPath("$.ignoreRate").value(33.3))
                .andExpect(jsonPath("$.reopenRate").value(0.0))
                .andExpect(jsonPath("$.highSeverityFixRate").value(50.0))
                .andExpect(jsonPath("$.averageResponseTimeSeconds").value(180.0))
                .andExpect(jsonPath("$.repeatedVulnerabilityCount").value(1))
                // fix < 80; ignore < 40; high-severity fix 50 is not < 50; reopen 0; 1 repeated type
                .andExpect(jsonPath("$.behaviourClassification").value("SECURITY_NEUTRAL"));
    }

    @Test
    void behaviourSummary_noEvents_shouldReturnZeroRatesAndInsufficientData() throws Exception {
        Long emptyDeveloper = createDeveloper("lifecycle-contract-empty");

        mockMvc.perform(get("/api/developer-behaviour/{id}", emptyDeveloper))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalSecurityEvents").value(0))
                .andExpect(jsonPath("$.fixRate").value(0.0))
                .andExpect(jsonPath("$.highSeverityFixRate").value(nullValue()))
                .andExpect(jsonPath("$.averageResponseTimeSeconds").value(0.0))
                .andExpect(jsonPath("$.behaviourClassification").value("INSUFFICIENT_DATA"));
    }

    @Test
    void behaviourSummary_unknownDeveloper_shouldReturn404() throws Exception {
        mockMvc.perform(get("/api/developer-behaviour/{id}", 919_191L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", "/api/developer-behaviour/919191"))
                .andExpect(jsonPath("$.message").value("Developer not found with id: '919191'"));
    }
}
