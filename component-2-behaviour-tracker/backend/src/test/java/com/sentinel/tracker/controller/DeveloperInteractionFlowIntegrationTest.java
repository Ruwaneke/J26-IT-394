package com.sentinel.tracker.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests of the action write path through the real controller, service and
 * H2 database, using the requests C1 sends.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DeveloperInteractionFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private DeveloperRepository developerRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private BehaviourLogRepository behaviourLogRepository;

    @Autowired
    private VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    private Long developerId;
    private Long eventId;

    @BeforeEach
    void setUp() throws Exception {
        developerId = developerRepository.save(
                Developer.builder().developerIdentifier("flow-dev").build()).getId();

        String body = mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"developerId\":" + developerId + ",\"vulnerabilityType\":\"SQL_INJECTION\","
                                + "\"severity\":\"HIGH\",\"fileName\":\"UserDao.java\",\"lineNumber\":42,"
                                + "\"message\":\"Unparameterised query\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        JsonNode created = objectMapper.readTree(body);
        eventId = created.get("id").asLong();
    }

    @AfterEach
    void tearDown() {
        lifecycleHistoryRepository.deleteAll();
        behaviourLogRepository.deleteAll();
        securityEventRepository.deleteAll();
        developerRepository.deleteAll();
    }

    @Test
    void secondOpen_shouldReturn201AndAddNoHistoryRow() throws Exception {
        sendAction(BehaviourAction.OPEN).andExpect(status().isCreated());
        sendAction(BehaviourAction.OPEN)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.action").value("OPEN"));

        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(2);
        assertThat(currentStatus()).isEqualTo(SecurityEventStatus.OPENED);
        // DETECTED (creation) + OPENED; the repeated OPEN adds nothing
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByChangedAtAsc(eventId)).hasSize(2);
    }

    @Test
    void dismissAfterIgnore_shouldReturn201AndAddNoHistoryRow() throws Exception {
        sendAction(BehaviourAction.IGNORE).andExpect(status().isCreated());
        sendAction(BehaviourAction.DISMISS).andExpect(status().isCreated());

        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(2);
        assertThat(currentStatus()).isEqualTo(SecurityEventStatus.IGNORED);
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByChangedAtAsc(eventId)).hasSize(2);
    }

    @Test
    void openOnFixed_shouldReturn409AndStoreNothing() throws Exception {
        sendAction(BehaviourAction.FIX).andExpect(status().isCreated());

        sendAction(BehaviourAction.OPEN)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message", containsString("cannot move from FIXED to OPENED")));

        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(1);
        assertThat(currentStatus()).isEqualTo(SecurityEventStatus.FIXED);
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByChangedAtAsc(eventId)).hasSize(2);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResultActions sendAction(BehaviourAction action) throws Exception {
        return mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"developerId\":" + developerId + ",\"securityEventId\":" + eventId
                        + ",\"action\":\"" + action + "\",\"sessionId\":\"s-1\",\"source\":\"VSCODE\"}"));
    }

    private SecurityEventStatus currentStatus() {
        return securityEventRepository.findById(eventId).orElseThrow().getCurrentStatus();
    }
}
