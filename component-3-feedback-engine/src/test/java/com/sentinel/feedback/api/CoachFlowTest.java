package com.sentinel.feedback.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Plan B end to end: delivery channels, fatigue limits, de-escalation, explanations and logging. */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class CoachFlowTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper json;

    @Test
    void overwhelmedDeveloperGetsQuieterDeliveryButSecretsStillInterrupt() throws Exception {
        String dev = "flow-overwhelmed";
        List<String> channels = new ArrayList<>();
        for (String file : List.of("A.java", "B.java", "C.java", "D.java")) {
            channels.add(decide(dev, "CWE-89", "HIGH", file, 3, 2, 0, 2).get("channel").asText());
        }
        // Same issue in A.java again: cooldown applies before the budget.
        JsonNode repeat = decide(dev, "CWE-89", "HIGH", "A.java", 3, 2, 0, 2);
        // A hardcoded secret is exempt from both.
        JsonNode secret = decide(dev, "CWE-798", "HIGH", "Config.java", 3, 2, 0, 2);

        assertEquals(List.of("TOAST_PANEL", "TOAST_PANEL", "TOAST_PANEL", "INLINE_HOVER"), channels);
        assertEquals("INLINE", repeat.get("channel").asText());
        assertTrue(repeat.get("deliveryNotes").get(0).asText().contains("cooldown"));
        assertEquals("TOAST_PANEL", secret.get("channel").asText());
        assertTrue(secret.get("deliveryNotes").get(0).asText().contains("never quietened"));

        mockMvc.perform(get("/api/v1/analytics/fatigue").param("dev", dev))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.interruptionsLastHour").value(4))
                .andExpect(jsonPath("$.fatigueIndex").value(4.0 / 3))
                .andExpect(jsonPath("$.decisionsLast24h").value(6));
    }

    @Test
    void threeQuickFixesLowerTheNextLevel() throws Exception {
        String dev = "flow-improving";
        for (int i = 0; i < 3; i++) {
            String id = decide(dev, "CWE-89", "HIGH", "F" + i + ".java", 3, 1, 0, 1).get("decisionId").asText();
            mockMvc.perform(post("/api/v1/feedback/" + id + "/outcome")
                            .contentType(MediaType.APPLICATION_JSON).content("{\"outcome\":\"FIXED\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.quickFix").value(true));
        }

        JsonNode next = decide(dev, "CWE-89", "HIGH", "F9.java", 3, 1, 0, 1);
        assertTrue(next.get("adjustments").toString().contains("fixed within 10 minutes"), next.toString());
    }

    @Test
    void explainReturnsStoredDecisionNarrativeAndMasteryTrend() throws Exception {
        String dev = "flow-explain";
        mockMvc.perform(post("/api/v1/skills/" + dev + "/events")
                .contentType(MediaType.APPLICATION_JSON).content("{\"cwe\":\"CWE-89\",\"eventType\":\"REPEAT\"}"));
        String id = decide(dev, "CWE-89", "HIGH", "X.java", 3, 2, 0, 2).get("decisionId").asText();

        mockMvc.perform(get("/api/v1/feedback/" + id + "/explain"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision.decisionId").value(id))
                .andExpect(jsonPath("$.decision.breakdown.repeat").value(20.0))
                .andExpect(jsonPath("$.decision.narrative").value(containsString("That is why you see L3 Coach")))
                .andExpect(jsonPath("$.file").value("X.java"))
                .andExpect(jsonPath("$.masteryHistory.length()").value(1));
    }

    @Test
    void dismissingWithoutExpandingIsAQuickDismissal() throws Exception {
        String id = decide("flow-dismiss", "CWE-79", "MEDIUM", "V.java", 0, 0, 0, null).get("decisionId").asText();

        interaction(id, "SHOWN").andExpect(status().isOk());
        interaction(id, "DISMISSED")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.quickDismiss").value(true));

        String expandedId = decide("flow-dismiss", "CWE-79", "MEDIUM", "W.java", 0, 0, 0, null)
                .get("decisionId").asText();
        interaction(expandedId, "SHOWN");
        interaction(expandedId, "EXPANDED");
        interaction(expandedId, "DISMISSED").andExpect(jsonPath("$.quickDismiss").value(false));

        mockMvc.perform(get("/api/v1/analytics/fatigue").param("dev", "flow-dismiss"))
                .andExpect(jsonPath("$.quickDismissalsLast24h").value(1));
    }

    @Test
    void outcomeUpdatesMasteryOnceAndVotesAreCounted() throws Exception {
        String dev = "flow-outcome";
        String id = decide(dev, "CWE-89", "HIGH", "O.java", 0, 0, 0, null).get("decisionId").asText();

        mockMvc.perform(post("/api/v1/feedback/" + id + "/outcome")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"outcome\":\"IGNORED\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.masteryAfter").value(0.425));
        mockMvc.perform(post("/api/v1/feedback/" + id + "/outcome")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"outcome\":\"FIXED\"}"))
                .andExpect(status().isConflict());

        mockMvc.perform(post("/api/v1/feedback/" + id + "/vote")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"vote\":\"TOO_MUCH\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/analytics/fatigue").param("dev", dev))
                .andExpect(jsonPath("$.tooMuchVotesLast24h").value(1));
    }

    @Test
    void unknownDecisionIsNotFound() throws Exception {
        mockMvc.perform(get("/api/v1/feedback/dec-missing/explain")).andExpect(status().isNotFound());
        interaction("dec-missing", "SHOWN").andExpect(status().isNotFound());
    }

    private JsonNode decide(String dev, String cwe, String severity, String file, int repeats, int ignores,
                            int reopened, Integer lastSimilar) throws Exception {
        String body = """
                {"event": {"eventId": "e-%s", "cwe": "%s", "severity": "%s", "language": "java", "file": "%s"},
                 "history": {"devHash": "%s", "repeats30d": %d, "ignored30d": %d, "fixed30d": 0,
                             "reopened30d": %d, "lastSimilarDaysAgo": %s}}
                """.formatted(file, cwe, severity, file, dev, repeats, ignores, reopened, lastSimilar);
        String response = mockMvc.perform(post("/api/v1/feedback/decide")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response);
    }

    private ResultActions interaction(String id, String type) throws Exception {
        return mockMvc.perform(post("/api/v1/feedback/" + id + "/interaction")
                .contentType(MediaType.APPLICATION_JSON).content("{\"type\":\"" + type + "\"}"));
    }
}
