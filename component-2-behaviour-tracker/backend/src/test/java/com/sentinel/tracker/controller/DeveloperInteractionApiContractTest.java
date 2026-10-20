package com.sentinel.tracker.controller;

import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract tests for {@code /api/developer-interactions} on the real stack (TASKS P1-5).
 * {@code POST} is used by C1 and is frozen (TECHNICAL_OVERVIEW §0 rule 1).
 */
class DeveloperInteractionApiContractTest extends ApiContractTestSupport {

    private static final String PATH = "/api/developer-interactions";

    private Long developerId;
    private Long eventId;

    @BeforeEach
    void setUp() throws Exception {
        developerId = createDeveloper("interaction-contract-dev");
        eventId = createEvent(String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"2026-10-20T10:00:00\"}"));
    }

    // ── POST: success ─────────────────────────────────────────────────────────

    @Test
    void create_c1Body_shouldReturn201WithFullResponse() throws Exception {
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T10:02:30")
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.securityEventId").value(eventId))
                .andExpect(jsonPath("$.developerId").value(developerId))
                .andExpect(jsonPath("$.action").value("OPEN"))
                .andExpect(jsonPath("$.actionTimestamp").value("2026-10-20T10:02:30"))
                .andExpect(jsonPath("$.timeSinceDetectionSeconds").value(150))
                .andExpect(jsonPath("$.sessionId").value("SESSION-TEST"))
                .andExpect(jsonPath("$.source").value("VSCODE"))
                .andExpect(jsonPath("$.metadata").value("{\"extensionAction\":\"EXPLANATION_VIEWED\",\"confidence\":0.92}"))
                .andExpect(jsonPath("$.createdAt").isString());
    }

    @Test
    void create_withoutActionTimestamp_shouldUseServerTime() throws Exception {
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);

        Long logId = json(sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated()))
                .get("id").asLong();

        BehaviourLog log = behaviourLogRepository.findById(logId).orElseThrow();
        assertThat(log.getTimestamp()).isAfter(before).isBefore(LocalDateTime.now().plusSeconds(1));
    }

    @Test
    void create_onlyRequiredFields_shouldReturn201WithNullOptionalFields() throws Exception {
        postJson(PATH, "{\"securityEventId\":" + eventId + ",\"developerId\":" + developerId + ",\"action\":\"FIX\"}")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sessionId").doesNotExist())
                .andExpect(jsonPath("$.source").doesNotExist())
                .andExpect(jsonPath("$.metadata").doesNotExist());
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
    }

    @Test
    void create_actionBeforeDetection_shouldStoreANegativeResponseTime() throws Exception {
        // actionTimestamp comes from the client and is not checked against detectedAt
        sendAction(developerId, eventId, BehaviourAction.OPEN, "2026-10-20T09:59:00")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.timeSinceDetectionSeconds").value(-60));
    }

    @Test
    void create_malformedMetadata_isStoredAsSent() throws Exception {
        // metadata is a free-form string; C2 does not parse it on write
        postJson(PATH, "{\"securityEventId\":" + eventId + ",\"developerId\":" + developerId
                + ",\"action\":\"OPEN\",\"metadata\":\"{not json\"}")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.metadata").value("{not json"));
    }

    // ── POST: validation ──────────────────────────────────────────────────────

    @Test
    void create_emptyObject_shouldReportEveryRequiredField() throws Exception {
        postJson(PATH, "{}")
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message", containsString("securityEventId must not be null")))
                .andExpect(jsonPath("$.message", containsString("developerId must not be null")))
                .andExpect(jsonPath("$.message", containsString("action must not be null")));
        assertThat(behaviourLogRepository.count()).isZero();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "securityEventId | securityEventId must not be null",
            "developerId     | developerId must not be null",
            "action          | action must not be null"
    })
    void create_nullRequiredField_shouldReturn400(String field, String message) throws Exception {
        String body = actionBody(developerId, eventId, BehaviourAction.OPEN, null)
                .replaceFirst("\"" + field + "\":(\"[A-Z]+\"|\\d+)", "\"" + field + "\":null");

        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(message));
        assertThat(behaviourLogRepository.count()).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"open", "VIEW", "FALSE_POSITIVE", ""})
    void create_invalidAction_shouldReturn400AndStoreNothing(String action) throws Exception {
        postJson(PATH, actionBody(developerId, eventId, action, null))
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH));

        assertThat(behaviourLogRepository.count()).isZero();
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.DETECTED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-10-20", "2026-10-20T10:00:00+05:30", "20/10/2026", "now", "2026-10-32T10:00:00"})
    void create_invalidActionTimestamp_shouldReturn400AndStoreNothing(String timestamp) throws Exception {
        sendAction(developerId, eventId, BehaviourAction.OPEN, timestamp)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("Invalid request body")));

        assertThat(behaviourLogRepository.count()).isZero();
    }

    @Test
    void create_sessionIdAndSourceTooLong_shouldReturn400() throws Exception {
        postJson(PATH, "{\"securityEventId\":" + eventId + ",\"developerId\":" + developerId
                + ",\"action\":\"OPEN\",\"sessionId\":\"" + "s".repeat(256) + "\",\"source\":\"" + "v".repeat(256) + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("sessionId must be at most 255 characters")))
                .andExpect(jsonPath("$.message", containsString("source must be at most 255 characters")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "not json", "[]", "{\"action\":}"})
    void create_malformedBody_shouldReturn400(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH));
        assertThat(behaviourLogRepository.count()).isZero();
    }

    @Test
    void create_wrongIdType_shouldReturn400() throws Exception {
        postJson(PATH, "{\"securityEventId\":\"first\",\"developerId\":" + developerId + ",\"action\":\"OPEN\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("not a valid `java.lang.Long` value")));
    }

    // ── POST: not found and ownership ─────────────────────────────────────────

    @Test
    void create_unknownDeveloper_shouldReturn404AndStoreNothing() throws Exception {
        sendAction(777_777L, eventId, BehaviourAction.FIX)
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH))
                .andExpect(jsonPath("$.message").value("Developer not found with id: '777777'"));

        assertNothingStored();
    }

    @Test
    void create_unknownEvent_shouldReturn404AndStoreNothing() throws Exception {
        sendAction(developerId, 888_888L, BehaviourAction.FIX)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Security event not found with id: '888888'"));

        assertNothingStored();
    }

    @Test
    void create_otherDevelopersEvent_shouldReturn403AndStoreNothing() throws Exception {
        Long intruderId = createDeveloper("interaction-contract-intruder");

        sendAction(intruderId, eventId, BehaviourAction.FIX)
                .andExpect(status().isForbidden())
                .andExpect(apiError(403, "Forbidden", PATH))
                .andExpect(jsonPath("$.message").value(
                        "Developer " + intruderId + " is not allowed to act on security event " + eventId));

        assertNothingStored();
    }

    @Test
    void create_otherDevelopersEventWithInvalidTransition_shouldReturn403Not409() throws Exception {
        sendAction(developerId, eventId, BehaviourAction.FIX).andExpect(status().isCreated());
        Long intruderId = createDeveloper("interaction-contract-intruder");

        // OPEN on FIXED would be 409 for the owner; the ownership check comes first
        sendAction(intruderId, eventId, BehaviourAction.OPEN).andExpect(status().isForbidden());

        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(1);
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
    }

    @Test
    void create_unknownDeveloperAndUnknownEvent_shouldReportTheDeveloperFirst() throws Exception {
        sendAction(777_777L, 888_888L, BehaviourAction.OPEN)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message", containsString("Developer")));
    }

    // ── GET ───────────────────────────────────────────────────────────────────

    @Test
    void getById_shouldReturn200() throws Exception {
        Long logId = json(sendAction(developerId, eventId, BehaviourAction.OPEN)).get("id").asLong();

        mockMvc.perform(get(PATH + "/{id}", logId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(logId))
                .andExpect(jsonPath("$.securityEventId").value(eventId))
                .andExpect(jsonPath("$.developerId").value(developerId))
                .andExpect(jsonPath("$.action").value("OPEN"));
    }

    @Test
    void getById_unknown_shouldReturn404() throws Exception {
        mockMvc.perform(get(PATH + "/{id}", 31_337L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/31337"))
                .andExpect(jsonPath("$.message").value("Developer interaction not found with id: '31337'"));
    }

    @Test
    void getAll_byDeveloper_andByEvent_shouldReturnTheStoredInteractions() throws Exception {
        sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.FIX).andExpect(status().isCreated());

        mockMvc.perform(get(PATH)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(2)));
        mockMvc.perform(get(PATH + "/developer/{id}", developerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));
        mockMvc.perform(get(PATH + "/security-event/{id}", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].securityEventId", org.hamcrest.Matchers.everyItem(
                        org.hamcrest.Matchers.equalTo(eventId.intValue()))));
    }

    @Test
    void getByDeveloperOrEvent_withNoInteractions_shouldReturnEmptyLists() throws Exception {
        mockMvc.perform(get(PATH + "/developer/{id}", developerId)).andExpect(jsonPath("$", hasSize(0)));
        mockMvc.perform(get(PATH + "/security-event/{id}", eventId)).andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getByDeveloperOrEvent_unknown_shouldReturn404() throws Exception {
        mockMvc.perform(get(PATH + "/developer/{id}", 404_404L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/developer/404404"));
        mockMvc.perform(get(PATH + "/security-event/{id}", 404_404L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/security-event/404404"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void assertNothingStored() {
        assertThat(behaviourLogRepository.count()).isZero();
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(lifecycleHistoryRepository.countBySecurityEventId(eventId)).isEqualTo(1);
    }
}
