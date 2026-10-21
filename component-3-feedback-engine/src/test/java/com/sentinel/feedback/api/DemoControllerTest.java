package com.sentinel.feedback.api;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DemoControllerTest {

    @Test
    void demonstratesScoringEscalationAndRecommendationWithMockData() {
        DemoController controller = new DemoController(
                new com.sentinel.feedback.scoring.SeverityScoringService(),
                new com.sentinel.feedback.scoring.FeedbackEscalationService(),
                new com.sentinel.feedback.recommendation.RecommendationTemplateService());

        DemoController.DemoResponse response = controller.demonstrate();

        assertEquals(75, response.baseScore().score());
        assertEquals("CRITICAL", response.escalatedScore().severity().name());
        assertEquals("SQL_INJECTION", response.event().vulnerabilityType().name());
        assertTrue(response.recommendation().guidance().contains("parameter"));
        assertTrue(response.vulnerableCode().contains("userId"));
        assertTrue(response.errorMessage().contains("untrusted user input"));
        assertTrue(response.correctedCode().contains("PreparedStatement"));
        assertTrue(response.sourceFilePath().endsWith("UserController.java"));
        assertTrue(response.vscodeFileUri().startsWith("vscode://file/"));
        assertTrue(response.vscodeFileUri().endsWith(":5:1"));
        assertEquals(3, response.findings().size());
        assertTrue(response.findings().stream()
                .anyMatch(finding -> finding.vulnerability().equals("XSS")));
        assertTrue(response.findings().stream()
                .anyMatch(finding -> finding.vulnerability().equals("HARDCODED_SECRET")));
    }
}
