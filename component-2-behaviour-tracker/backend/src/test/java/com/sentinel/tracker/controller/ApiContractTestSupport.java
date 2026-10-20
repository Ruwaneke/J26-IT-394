package com.sentinel.tracker.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Shared set-up for the API contract tests (TASKS P1-5): the real controllers, services and
 * H2 database of the test profile, never PostgreSQL. Every test deletes the rows it wrote.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
abstract class ApiContractTestSupport {

    /** The body C1 sends for a detection (sentinel/src/events/securityEventClient.ts). */
    static final String C1_EVENT_BODY = "{\"developerId\":%d,\"vulnerabilityType\":\"SQL_INJECTION\","
            + "\"severity\":\"HIGH\",\"fileName\":\"/workspace/app/UserDao.java\",\"lineNumber\":42,"
            + "\"message\":\"Unparameterised query\"}";

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    DeveloperRepository developerRepository;

    @Autowired
    SecurityEventRepository securityEventRepository;

    @Autowired
    BehaviourLogRepository behaviourLogRepository;

    @Autowired
    VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    @AfterEach
    void deleteTestRows() {
        lifecycleHistoryRepository.deleteAll();
        behaviourLogRepository.deleteAll();
        securityEventRepository.deleteAll();
        developerRepository.deleteAll();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    Long createDeveloper(String identifier) {
        return developerRepository.save(Developer.builder().developerIdentifier(identifier).build()).getId();
    }

    ResultActions postJson(String path, String body) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    Long createEvent(Long developerId) throws Exception {
        return createEvent(String.format(C1_EVENT_BODY, developerId));
    }

    Long createEvent(String body) throws Exception {
        String response = postJson("/api/security-events", body)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).get("id").asLong();
    }

    /** The body C1 sends for an action, plus an optional {@code actionTimestamp}. */
    static String actionBody(Long developerId, Long eventId, Object action, String actionTimestamp) {
        return "{\"securityEventId\":" + eventId + ",\"developerId\":" + developerId
                + ",\"action\":\"" + action + "\",\"sessionId\":\"SESSION-TEST\",\"source\":\"VSCODE\","
                + "\"metadata\":\"{\\\"extensionAction\\\":\\\"EXPLANATION_VIEWED\\\",\\\"confidence\\\":0.92}\""
                + (actionTimestamp != null ? ",\"actionTimestamp\":\"" + actionTimestamp + "\"" : "")
                + "}";
    }

    ResultActions sendAction(Long developerId, Long eventId, BehaviourAction action) throws Exception {
        return sendAction(developerId, eventId, action, null);
    }

    ResultActions sendAction(Long developerId, Long eventId, BehaviourAction action, String actionTimestamp)
            throws Exception {
        return postJson("/api/developer-interactions", actionBody(developerId, eventId, action, actionTimestamp));
    }

    JsonNode json(ResultActions result) throws Exception {
        return objectMapper.readTree(result.andReturn().getResponse().getContentAsString());
    }

    SecurityEvent event(Long eventId) {
        return securityEventRepository.findById(eventId).orElseThrow();
    }

    SecurityEventStatus currentStatus(Long eventId) {
        return event(eventId).getCurrentStatus();
    }

    /** The {@code ApiErrorResponse} body produced by {@code GlobalExceptionHandler}. */
    static ResultMatcher apiError(int status, String error, String path) {
        return result -> {
            content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON).match(result);
            jsonPath("$.timestamp").isString().match(result);
            jsonPath("$.status").value(status).match(result);
            jsonPath("$.error").value(error).match(result);
            jsonPath("$.message").isString().match(result);
            jsonPath("$.path").value(path).match(result);
        };
    }
}
