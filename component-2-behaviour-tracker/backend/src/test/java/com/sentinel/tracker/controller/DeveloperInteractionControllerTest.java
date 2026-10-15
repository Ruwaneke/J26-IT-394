package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.exception.AccessDeniedException;
import com.sentinel.tracker.exception.InvalidStatusTransitionException;
import com.sentinel.tracker.service.DeveloperInteractionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

@WebMvcTest(DeveloperInteractionController.class)
@ActiveProfiles("test")
class DeveloperInteractionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DeveloperInteractionService developerInteractionService;

    @Test
    void createInteraction_shouldReturn201() throws Exception {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        request.setDeveloperId(1L);
        request.setSecurityEventId(1L);
        request.setAction(BehaviourAction.OPEN);

        DeveloperInteractionResponse response = DeveloperInteractionResponse.builder()
                .id(1L)
                .developerId(1L)
                .securityEventId(1L)
                .action(BehaviourAction.OPEN)
                .build();

        when(developerInteractionService.createInteraction(any())).thenReturn(response);

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.action", is("OPEN")));
    }

    @Test
    void createInteraction_invalidRequest_shouldReturn400() throws Exception {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        // Missing required fields developerId, securityEventId, action

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getInteractionById_shouldReturn200() throws Exception {
        DeveloperInteractionResponse response = DeveloperInteractionResponse.builder()
                .id(1L)
                .developerId(1L)
                .action(BehaviourAction.OPEN)
                .build();

        when(developerInteractionService.getInteractionById(1L)).thenReturn(response);

        mockMvc.perform(get("/api/developer-interactions/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)));
    }

    @Test
    void getAllInteractions_shouldReturn200() throws Exception {
        when(developerInteractionService.getAllInteractions()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getInteractionsByDeveloper_shouldReturn200() throws Exception {
        when(developerInteractionService.getInteractionsByDeveloper(1L)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions/developer/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getInteractionsBySecurityEvent_shouldReturn200() throws Exception {
        when(developerInteractionService.getInteractionsBySecurityEvent(1L)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions/security-event/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    // ── Ownership ─────────────────────────────────────────────────────────────

    @Test
    void createInteraction_otherDevelopersEvent_shouldReturn403() throws Exception {
        when(developerInteractionService.createInteraction(any())).thenThrow(
                new AccessDeniedException("Developer 2 is not allowed to act on security event 1"));

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"developerId\":2,\"securityEventId\":1,\"action\":\"FIX\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status", is(403)))
                .andExpect(jsonPath("$.error", is("Forbidden")))
                .andExpect(jsonPath("$.message", containsString("not allowed")))
                .andExpect(jsonPath("$.path", is("/api/developer-interactions")));
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Test
    void createInteraction_invalidTransition_shouldReturn409() throws Exception {
        when(developerInteractionService.createInteraction(any())).thenThrow(
                new InvalidStatusTransitionException("Security event 1 cannot move from FIXED to OPENED "
                        + "(action OPEN); allowed next statuses: [REOPENED]"));

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"developerId\":1,\"securityEventId\":1,\"action\":\"OPEN\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status", is(409)))
                .andExpect(jsonPath("$.error", is("Conflict")))
                .andExpect(jsonPath("$.message", containsString("cannot move from FIXED to OPENED")))
                .andExpect(jsonPath("$.path", is("/api/developer-interactions")));
    }

    // ── Invalid requests ──────────────────────────────────────────────────────

    private CreateDeveloperInteractionRequest validRequest() {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        request.setDeveloperId(1L);
        request.setSecurityEventId(1L);
        request.setAction(BehaviourAction.OPEN);
        return request;
    }

    @Test
    void createInteraction_sessionIdTooLong_shouldReturn400() throws Exception {
        CreateDeveloperInteractionRequest request = validRequest();
        request.setSessionId("s".repeat(256));

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.message", containsString("sessionId must be at most 255 characters")));

        verifyNoInteractions(developerInteractionService);
    }

    @Test
    void createInteraction_sourceTooLong_shouldReturn400() throws Exception {
        CreateDeveloperInteractionRequest request = validRequest();
        request.setSource("v".repeat(256));

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("source must be at most 255 characters")));

        verifyNoInteractions(developerInteractionService);
    }

    @Test
    void createInteraction_sessionIdAndSourceTooLong_shouldReportBothErrors() throws Exception {
        CreateDeveloperInteractionRequest request = validRequest();
        request.setSessionId("s".repeat(300));
        request.setSource("v".repeat(300));

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", allOf(
                        containsString("sessionId must be at most 255 characters"),
                        containsString("source must be at most 255 characters"))));

        verifyNoInteractions(developerInteractionService);
    }

    @Test
    void createInteraction_sessionIdAndSourceAtMaxLength_shouldReturn201() throws Exception {
        CreateDeveloperInteractionRequest request = validRequest();
        request.setSessionId("s".repeat(255));
        request.setSource("v".repeat(255));

        when(developerInteractionService.createInteraction(any())).thenReturn(
                DeveloperInteractionResponse.builder().id(1L).action(BehaviourAction.OPEN).build());

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    void createInteraction_missingAction_shouldReturn400WithMessage() throws Exception {
        CreateDeveloperInteractionRequest request = validRequest();
        request.setAction(null);

        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("action must not be null")));

        verifyNoInteractions(developerInteractionService);
    }

    @Test
    void createInteraction_unknownAction_shouldReturn400() throws Exception {
        mockMvc.perform(post("/api/developer-interactions")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"developerId\":1,\"securityEventId\":1,\"action\":\"DELETE\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status", is(400)));

        verifyNoInteractions(developerInteractionService);
    }
}
