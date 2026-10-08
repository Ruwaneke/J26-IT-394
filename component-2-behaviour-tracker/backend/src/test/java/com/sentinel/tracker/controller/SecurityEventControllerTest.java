package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.SecurityEventResponse;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.GlobalExceptionHandler;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.service.SecurityEventService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Phase 02 – Controller-layer integration tests for SecurityEventController.
 *
 * Uses @WebMvcTest (Spring MVC slice only, no full context) with MockMvc.
 * Verifies HTTP status codes, response body structure, and validation behaviour.
 */
@WebMvcTest(SecurityEventController.class)
@Import(GlobalExceptionHandler.class)
class SecurityEventControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private SecurityEventService securityEventService;

    private SecurityEventResponse sampleResponse;

    @BeforeEach
    void setUp() {
        sampleResponse = SecurityEventResponse.builder()
                .id(1L)
                .developerId(10L)
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserService.java")
                .lineNumber(45)
                .message("Possible SQL injection vulnerability")
                .detectedAt(LocalDateTime.of(2026, 8, 10, 14, 0, 0))
                .currentStatus(SecurityEventStatus.DETECTED)
                .createdAt(LocalDateTime.of(2026, 8, 10, 14, 0, 0))
                .updatedAt(LocalDateTime.of(2026, 8, 10, 14, 0, 0))
                .build();
    }

    // ── POST /api/security-events ─────────────────────────────────────────────

    @Test
    @DisplayName("POST /api/security-events – 201 Created with valid request")
    void createSecurityEvent_shouldReturn201WithValidRequest() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();

        when(securityEventService.createSecurityEvent(any(CreateSecurityEventRequest.class)))
                .thenReturn(sampleResponse);

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.developerId").value(10))
                .andExpect(jsonPath("$.vulnerabilityType").value("SQL_INJECTION"))
                .andExpect(jsonPath("$.severity").value("HIGH"))
                .andExpect(jsonPath("$.fileName").value("UserService.java"))
                .andExpect(jsonPath("$.lineNumber").value(45))
                .andExpect(jsonPath("$.currentStatus").value("DETECTED"))
                .andExpect(jsonPath("$.detectedAt").isNotEmpty());
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when developerId is null")
    void createSecurityEvent_shouldReturn400WhenDeveloperIdNull() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();
        request.setDeveloperId(null);

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when vulnerabilityType is blank")
    void createSecurityEvent_shouldReturn400WhenVulnerabilityTypeBlank() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();
        request.setVulnerabilityType("");

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when fileName is blank")
    void createSecurityEvent_shouldReturn400WhenFileNameBlank() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();
        request.setFileName("");

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when message is blank")
    void createSecurityEvent_shouldReturn400WhenMessageBlank() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();
        request.setMessage("");

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when lineNumber is negative")
    void createSecurityEvent_shouldReturn400WhenLineNumberNegative() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();
        request.setLineNumber(-1);

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when severity is null")
    void createSecurityEvent_shouldReturn400WhenSeverityNull() throws Exception {
        // Send raw JSON with severity omitted (null)
        String json = """
                {
                  "developerId": 10,
                  "vulnerabilityType": "SQL_INJECTION",
                  "fileName": "UserService.java",
                  "lineNumber": 45,
                  "message": "Possible SQL injection"
                }
                """;

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 400 when severity is invalid enum string")
    void createSecurityEvent_shouldReturn400WhenSeverityInvalid() throws Exception {
        String json = """
                {
                  "developerId": 10,
                  "vulnerabilityType": "SQL_INJECTION",
                  "severity": "EXTREME",
                  "fileName": "UserService.java",
                  "lineNumber": 45,
                  "message": "Possible SQL injection"
                }
                """;

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("POST /api/security-events – 404 when developer not found")
    void createSecurityEvent_shouldReturn404WhenDeveloperNotFound() throws Exception {
        CreateSecurityEventRequest request = buildValidRequest();

        when(securityEventService.createSecurityEvent(any(CreateSecurityEventRequest.class)))
                .thenThrow(new ResourceNotFoundException("Developer", "id", 10L));

        mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message", containsString("Developer")));
    }

    // ── GET /api/security-events/{id} ─────────────────────────────────────────

    @Test
    @DisplayName("GET /api/security-events/{id} – 200 with existing event")
    void getSecurityEventById_shouldReturn200() throws Exception {
        when(securityEventService.getSecurityEventById(1L)).thenReturn(sampleResponse);

        mockMvc.perform(get("/api/security-events/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.vulnerabilityType").value("SQL_INJECTION"))
                .andExpect(jsonPath("$.currentStatus").value("DETECTED"));
    }

    @Test
    @DisplayName("GET /api/security-events/{id} – 404 when event not found")
    void getSecurityEventById_shouldReturn404WhenNotFound() throws Exception {
        when(securityEventService.getSecurityEventById(999L))
                .thenThrow(new ResourceNotFoundException("Security event", "id", 999L));

        mockMvc.perform(get("/api/security-events/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.message", containsString("999")));
    }

    // ── GET /api/security-events ───────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/security-events – 200 with list of events")
    void getAllSecurityEvents_shouldReturn200WithList() throws Exception {
        when(securityEventService.getAllSecurityEvents()).thenReturn(List.of(sampleResponse));

        mockMvc.perform(get("/api/security-events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].severity").value("HIGH"));
    }

    @Test
    @DisplayName("GET /api/security-events – 200 with empty list")
    void getAllSecurityEvents_shouldReturn200WithEmptyList() throws Exception {
        when(securityEventService.getAllSecurityEvents()).thenReturn(List.of());

        mockMvc.perform(get("/api/security-events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    // ── GET /api/security-events/developer/{developerId} ──────────────────────

    @Test
    @DisplayName("GET /api/security-events/developer/{developerId} – 200 with events")
    void getSecurityEventsByDeveloper_shouldReturn200() throws Exception {
        when(securityEventService.getSecurityEventsByDeveloper(10L))
                .thenReturn(List.of(sampleResponse));

        mockMvc.perform(get("/api/security-events/developer/10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].developerId").value(10));
    }

    @Test
    @DisplayName("GET /api/security-events/developer/{developerId} – 404 when developer not found")
    void getSecurityEventsByDeveloper_shouldReturn404WhenDeveloperNotFound() throws Exception {
        when(securityEventService.getSecurityEventsByDeveloper(999L))
                .thenThrow(new ResourceNotFoundException("Developer", "id", 999L));

        mockMvc.perform(get("/api/security-events/developer/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CreateSecurityEventRequest buildValidRequest() {
        CreateSecurityEventRequest req = new CreateSecurityEventRequest();
        req.setDeveloperId(10L);
        req.setVulnerabilityType("SQL_INJECTION");
        req.setSeverity(Severity.HIGH);
        req.setFileName("UserService.java");
        req.setLineNumber(45);
        req.setMessage("Possible SQL injection vulnerability");
        return req;
    }
}
