package com.sentinel.tracker.controller;

import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.SecurityEventStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract tests for {@code /api/security-events} on the real stack (TASKS P1-5).
 * {@code POST} is used by C1 and is frozen (TECHNICAL_OVERVIEW §0 rule 1).
 */
class SecurityEventApiContractTest extends ApiContractTestSupport {

    private static final String PATH = "/api/security-events";

    private Long developerId;

    @BeforeEach
    void setUp() {
        developerId = createDeveloper("event-contract-dev");
    }

    // ── POST: success ─────────────────────────────────────────────────────────

    @Test
    void create_c1Body_shouldReturn201WithFullResponseAndDetectedHistoryRow() throws Exception {
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);

        String response = postJson(PATH, String.format(C1_EVENT_BODY, developerId))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.developerId").value(developerId))
                .andExpect(jsonPath("$.vulnerabilityType").value("SQL_INJECTION"))
                .andExpect(jsonPath("$.severity").value("HIGH"))
                .andExpect(jsonPath("$.fileName").value("/workspace/app/UserDao.java"))
                .andExpect(jsonPath("$.lineNumber").value(42))
                .andExpect(jsonPath("$.message").value("Unparameterised query"))
                .andExpect(jsonPath("$.currentStatus").value("DETECTED"))
                .andExpect(jsonPath("$.detectedAt").isString())
                .andExpect(jsonPath("$.createdAt").isString())
                .andExpect(jsonPath("$.updatedAt").isString())
                .andReturn().getResponse().getContentAsString();

        Long eventId = objectMapper.readTree(response).get("id").asLong();
        // No detectedAt in the C1 body, so the server time is used
        assertThat(event(eventId).getDetectedAt()).isAfter(before).isBefore(LocalDateTime.now().plusSeconds(1));

        List<VulnerabilityLifecycleHistory> history = lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId);
        assertThat(history).hasSize(1);
        assertThat(history.get(0).getPreviousStatus()).isNull();
        assertThat(history.get(0).getNewStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(history.get(0).getChangedBy()).isEqualTo("SYSTEM");
        assertThat(history.get(0).getChangedAt()).isEqualTo(event(eventId).getDetectedAt());
    }

    @ParameterizedTest
    @ValueSource(strings = {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
    void create_everySeverity_shouldReturn201(String severity) throws Exception {
        postJson(PATH, String.format(C1_EVENT_BODY, developerId).replace("\"HIGH\"", "\"" + severity + "\""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.severity").value(severity));
    }

    @Test
    void create_lineNumberZero_shouldReturn201() throws Exception {
        postJson(PATH, String.format(C1_EVENT_BODY, developerId).replace("\"lineNumber\":42", "\"lineNumber\":0"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.lineNumber").value(0));
    }

    @Test
    void create_identicalRequestTwice_shouldCreateTwoEventsEachWithItsOwnHistory() throws Exception {
        // C2 does not de-duplicate detections; C1 does, by file + line + type
        Long first = createEvent(developerId);
        Long second = createEvent(developerId);

        assertThat(first).isNotEqualTo(second);
        assertThat(lifecycleHistoryRepository.countBySecurityEventId(first)).isEqualTo(1);
        assertThat(lifecycleHistoryRepository.countBySecurityEventId(second)).isEqualTo(1);
    }

    @Test
    void create_unknownJsonFields_shouldBeIgnored() throws Exception {
        String body = String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"currentStatus\":\"FIXED\",\"id\":999,\"confidence\":0.9}");

        postJson(PATH, body)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.currentStatus").value("DETECTED"))
                .andExpect(jsonPath("$.id").value(org.hamcrest.Matchers.not(999)));
    }

    // ── POST: timestamps (ISO-8601 local date-time) ───────────────────────────

    @Test
    void create_detectedAt_shouldBeStoredAndUsedForTheFirstHistoryRow() throws Exception {
        Long eventId = createEvent(withField("detectedAt", "\"2026-10-20T09:15:30\""));

        assertThat(event(eventId).getDetectedAt()).isEqualTo(LocalDateTime.of(2026, 10, 20, 9, 15, 30));
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId).get(0).getChangedAt())
                .isEqualTo(LocalDateTime.of(2026, 10, 20, 9, 15, 30));
    }

    @Test
    void create_timestampAlias_shouldSetDetectedAt() throws Exception {
        postJson(PATH, withField("timestamp", "\"2026-10-20T09:15:30\""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.detectedAt").value("2026-10-20T09:15:30"));
    }

    @Test
    void create_nanosecondDetectedAt_shouldBeTruncatedToMicroseconds() throws Exception {
        postJson(PATH, withField("detectedAt", "\"2026-10-20T09:15:30.123456789\""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.detectedAt").value("2026-10-20T09:15:30.123456"));
    }

    @Test
    void create_utcDesignator_isAcceptedAndTheZoneIsDropped() throws Exception {
        // Current behaviour (Jackson's lenient LocalDateTime parsing): "Z" is accepted and the
        // time is stored as written, not converted. C1 sends no timestamp, so it is unaffected.
        postJson(PATH, withField("detectedAt", "\"2026-10-20T09:15:30Z\""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.detectedAt").value("2026-10-20T09:15:30"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "\"2026-10-20T09:15:30+05:30\" | could not be parsed",
            "\"2026-10-20\"                | could not be parsed",
            "\"2026-13-20T09:15:30\"       | MonthOfYear",
            "\"2026-02-30T09:15:30\"       | Invalid date",
            "\"20/10/2026 09:15\"          | could not be parsed",
            "\"yesterday\"                 | could not be parsed",
            "1760000000000                 | raw timestamp"
    })
    void create_invalidDetectedAt_shouldReturn400AndStoreNothing(String value, String messageFragment)
            throws Exception {
        postJson(PATH, withField("detectedAt", value))
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message", containsString("Invalid request body")))
                .andExpect(jsonPath("$.message", containsString(messageFragment)));

        assertThat(securityEventRepository.count()).isZero();
    }

    // ── POST: validation ──────────────────────────────────────────────────────

    @Test
    void create_emptyObject_shouldReportEveryRequiredField() throws Exception {
        postJson(PATH, "{}")
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message", containsString("developerId must not be null")))
                .andExpect(jsonPath("$.message", containsString("vulnerabilityType must not be blank")))
                .andExpect(jsonPath("$.message", containsString("severity must not be null")))
                .andExpect(jsonPath("$.message", containsString("fileName must not be blank")))
                .andExpect(jsonPath("$.message", containsString("lineNumber must not be null")))
                .andExpect(jsonPath("$.message", containsString("message must not be blank")));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "vulnerabilityType | \"\"     | vulnerabilityType must not be blank",
            "vulnerabilityType | \"   \"  | vulnerabilityType must not be blank",
            "vulnerabilityType | null     | vulnerabilityType must not be blank",
            "fileName          | \"\"     | fileName must not be blank",
            "fileName          | null     | fileName must not be blank",
            "message           | \"  \"   | message must not be blank",
            "message           | null     | message must not be blank",
            "severity          | null     | severity must not be null",
            "lineNumber        | null     | lineNumber must not be null",
            "lineNumber        | -1       | lineNumber must be zero or positive",
            "developerId       | null     | developerId must not be null"
    })
    void create_invalidField_shouldReturn400WithFieldMessage(String field, String value, String message)
            throws Exception {
        postJson(PATH, withField(field, value))
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message").value(message));

        assertThat(securityEventRepository.count()).isZero();
    }

    @Test
    void create_valuesOverMaximumLength_shouldReturn400() throws Exception {
        postJson(PATH, withField("vulnerabilityType", "\"" + "T".repeat(256) + "\""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("vulnerabilityType must be at most 255 characters"));
        postJson(PATH, withField("fileName", "\"" + "f".repeat(501) + "\""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("fileName must be at most 500 characters"));
    }

    @Test
    void create_valuesAtMaximumLength_shouldReturn201() throws Exception {
        String body = withField("vulnerabilityType", "\"" + "T".repeat(255) + "\"")
                .replace("\"/workspace/app/UserDao.java\"", "\"" + "f".repeat(500) + "\"");
        postJson(PATH, body).andExpect(status().isCreated());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "severity    | \"high\"         | not one of the values accepted",
            "severity    | \"INFO\"         | not one of the values accepted",
            "lineNumber  | 99999999999      | out of range of int",
            "lineNumber  | \"forty-two\"    | Integer",
            "developerId | \"abc\"          | not a valid `java.lang.Long` value",
            "developerId | 99999999999999999999 | out of range of long"
    })
    void create_wrongTypeOrRange_shouldReturn400(String field, String value, String messageFragment)
            throws Exception {
        postJson(PATH, withField(field, value))
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message", containsString("Invalid request body")))
                .andExpect(jsonPath("$.message", containsString(messageFragment)));

        assertThat(securityEventRepository.count()).isZero();
    }

    @Test
    void create_emptyDetectedAt_isTreatedAsAbsent() throws Exception {
        // Current behaviour (Jackson coerces "" to null): the server time is used
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);
        Long eventId = createEvent(withField("detectedAt", "\"\""));
        assertThat(event(eventId).getDetectedAt()).isAfter(before);
    }

    @Test
    void create_numericSeverity_isReadAsTheEnumPosition() throws Exception {
        // Current behaviour (Jackson accepts enum ordinals by default): 3 is CRITICAL.
        // Recorded so a change is noticed; clients should send the name.
        postJson(PATH, withField("severity", "3"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.severity").value("CRITICAL"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "{\"developerId\":", "not json", "[]", "null"})
    void create_malformedOrMissingBody_shouldReturn400(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH));

        assertThat(securityEventRepository.count()).isZero();
    }

    @Test
    void create_unknownDeveloper_shouldReturn404AndStoreNothing() throws Exception {
        postJson(PATH, String.format(C1_EVENT_BODY, 987_654L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH))
                .andExpect(jsonPath("$.message").value("Developer not found with id: '987654'"));

        assertThat(securityEventRepository.count()).isZero();
        assertThat(lifecycleHistoryRepository.count()).isZero();
    }

    // ── GET ───────────────────────────────────────────────────────────────────

    @Test
    void getById_shouldReturn200WithTheStoredEvent() throws Exception {
        Long eventId = createEvent(developerId);

        mockMvc.perform(get(PATH + "/{id}", eventId))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").value(eventId))
                .andExpect(jsonPath("$.developerId").value(developerId))
                .andExpect(jsonPath("$.currentStatus").value("DETECTED"));
    }

    @Test
    void getById_unknownEvent_shouldReturn404() throws Exception {
        mockMvc.perform(get(PATH + "/{id}", 424_242L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/424242"))
                .andExpect(jsonPath("$.message").value("Security event not found with id: '424242'"));
    }

    @Test
    void getByDeveloper_shouldReturnOnlyThatDevelopersEvents() throws Exception {
        Long otherDeveloperId = createDeveloper("event-contract-other");
        Long own = createEvent(developerId);
        createEvent(otherDeveloperId);

        mockMvc.perform(get(PATH + "/developer/{id}", developerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].id").value(own));
    }

    @Test
    void getByDeveloper_developerWithoutEvents_shouldReturnEmptyList() throws Exception {
        mockMvc.perform(get(PATH + "/developer/{id}", developerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getByDeveloper_unknownDeveloper_shouldReturn404() throws Exception {
        mockMvc.perform(get(PATH + "/developer/{id}", 555_555L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/developer/555555"));
    }

    @Test
    void getAll_shouldReturnEveryEvent() throws Exception {
        createEvent(developerId);
        createEvent(developerId);

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The C1 body with one field replaced, added, or set to a raw JSON value. */
    private String withField(String field, String rawJsonValue) {
        String body = String.format(C1_EVENT_BODY, developerId);
        String pattern = "\"" + field + "\":";
        int start = body.indexOf(pattern);
        if (start < 0) {
            return body.substring(0, body.length() - 1) + "," + pattern + rawJsonValue + "}";
        }
        int valueStart = start + pattern.length();
        int valueEnd = body.charAt(valueStart) == '"'
                ? body.indexOf('"', valueStart + 1) + 1
                : indexOfAny(body, valueStart);
        return body.substring(0, valueStart) + rawJsonValue + body.substring(valueEnd);
    }

    private static int indexOfAny(String body, int from) {
        for (int i = from; i < body.length(); i++) {
            if (body.charAt(i) == ',' || body.charAt(i) == '}') {
                return i;
            }
        }
        return body.length();
    }
}
