package com.sentinel.feedback.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** End-to-end through the real policy.yaml. */
@SpringBootTest
@AutoConfigureMockMvc
class FeedbackControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void firstTimeSqlInjectionGetsGuideLevel() throws Exception {
        mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(decideBody("d-first", "CWE-89", "HIGH", 0, 0, "null")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.level").value(2))
                .andExpect(jsonPath("$.levelName").value("Guide"))
                .andExpect(jsonPath("$.score").value(33.75))
                .andExpect(jsonPath("$.breakdown.severity").value(26.25))
                .andExpect(jsonPath("$.mastery").value(0.5))
                .andExpect(jsonPath("$.policyVersion").value("1.1.0"))
                .andExpect(jsonPath("$.template.title").value("Use parameterized database queries"));
    }

    @Test
    void hardcodedSecretIsRaisedToCoach() throws Exception {
        mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(decideBody("d-secret", "CWE-798", "MEDIUM", 0, 0, "null")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.level").value(3))
                .andExpect(jsonPath("$.adjustments[0]").exists());
    }

    @Test
    void recordedSkillEventsChangeMasteryAndScore() throws Exception {
        mockMvc.perform(post("/api/v1/skills/d-repeat/events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"cwe\":\"CWE-89\",\"eventType\":\"REPEAT\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mastery").value(0.35));

        mockMvc.perform(get("/api/v1/skills/d-repeat"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].cweId").value("CWE-89"));

        mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(decideBody("d-repeat", "CWE-89", "HIGH", 0, 0, "null")))
                .andExpect(jsonPath("$.breakdown.weakness").value(9.75))
                .andExpect(jsonPath("$.score").value(36.0));
    }

    @Test
    void unsupportedCweIsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(decideBody("d-x", "CWE-0", "HIGH", 0, 0, "null")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingHistoryIsBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"event\":{\"eventId\":\"e-1\",\"cwe\":\"CWE-89\",\"severity\":\"HIGH\"}}"))
                .andExpect(status().isBadRequest());
    }

    private String decideBody(String devHash, String cwe, String severity, int repeats, int ignores,
                              String lastSimilarDaysAgo) {
        return """
                {
                  "event": {"eventId": "e-1", "cwe": "%s", "severity": "%s",
                            "language": "java", "line": 42, "snippet": "..."},
                  "history": {"devHash": "%s", "repeats30d": %d, "ignored30d": %d,
                              "fixed30d": 0, "reopened30d": 0, "lastSimilarDaysAgo": %s}
                }
                """.formatted(cwe, severity, devHash, repeats, ignores, lastSimilarDaysAgo);
    }
}
