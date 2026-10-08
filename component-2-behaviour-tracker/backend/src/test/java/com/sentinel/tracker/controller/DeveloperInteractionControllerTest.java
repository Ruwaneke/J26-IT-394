package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.service.BehaviourLogService;
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
    private BehaviourLogService behaviourLogService;

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

        when(behaviourLogService.createInteraction(any())).thenReturn(response);

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

        when(behaviourLogService.getInteractionById(1L)).thenReturn(response);

        mockMvc.perform(get("/api/developer-interactions/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(1)));
    }

    @Test
    void getAllInteractions_shouldReturn200() throws Exception {
        when(behaviourLogService.getAllInteractions()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getInteractionsByDeveloper_shouldReturn200() throws Exception {
        when(behaviourLogService.getInteractionsByDeveloper(1L)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions/developer/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void getInteractionsBySecurityEvent_shouldReturn200() throws Exception {
        when(behaviourLogService.getInteractionsBySecurityEvent(1L)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/developer-interactions/security-event/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }
}
