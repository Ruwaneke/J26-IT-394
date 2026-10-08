package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.service.BehaviourAnalysisService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

@WebMvcTest(DeveloperBehaviourController.class)
@ActiveProfiles("test")
class DeveloperBehaviourControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private BehaviourAnalysisService behaviourAnalysisService;

    @Test
    void getDeveloperBehaviourSummary_shouldReturn200() throws Exception {
        DeveloperBehaviourSummaryResponse response = DeveloperBehaviourSummaryResponse.builder()
                .developerId(1L)
                .behaviourClassification("SECURITY_RESPONSIVE")
                .fixRate(90.0)
                .build();

        when(behaviourAnalysisService.getDeveloperBehaviourSummary(1L)).thenReturn(response);

        mockMvc.perform(get("/api/developer-behaviour/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.developerId", is(1)))
                .andExpect(jsonPath("$.behaviourClassification", is("SECURITY_RESPONSIVE")))
                .andExpect(jsonPath("$.fixRate", is(90.0)));
    }
}
