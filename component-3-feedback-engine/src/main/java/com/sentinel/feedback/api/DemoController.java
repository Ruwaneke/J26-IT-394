package com.sentinel.feedback.api;

import com.sentinel.feedback.model.BehaviourHistory;
import com.sentinel.feedback.model.SecurityEvent;
import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.recommendation.RecommendationTemplate;
import com.sentinel.feedback.recommendation.RecommendationTemplateService;
import com.sentinel.feedback.scoring.FeedbackEscalationService;
import com.sentinel.feedback.scoring.SeverityScore;
import com.sentinel.feedback.scoring.SeverityScoringService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    private final SeverityScoringService severityScoringService;
    private final FeedbackEscalationService feedbackEscalationService;
    private final RecommendationTemplateService recommendationTemplateService;

    public DemoController(
            SeverityScoringService severityScoringService,
            FeedbackEscalationService feedbackEscalationService,
            RecommendationTemplateService recommendationTemplateService) {
        this.severityScoringService = severityScoringService;
        this.feedbackEscalationService = feedbackEscalationService;
        this.recommendationTemplateService = recommendationTemplateService;
    }

    @GetMapping("/demo")
    public DemoResponse demonstrate() {
        Path sampleFile = Path.of("src", "test", "resources", "demo", "UserController.java")
                .toAbsolutePath()
                .normalize();
        Path xssFile = Path.of("src", "test", "resources", "demo", "UserView.java")
                .toAbsolutePath()
                .normalize();
        Path secretFile = Path.of("src", "test", "resources", "demo", "Configuration.java")
                .toAbsolutePath()
                .normalize();
        SecurityEvent event = new SecurityEvent(
                "demo-event-001",
                "DEV001",
                "demo-session-001",
                VulnerabilityType.SQL_INJECTION,
                Severity.HIGH,
                0.95,
                sampleFile.toString(),
                5,
                Instant.parse("2026-10-16T00:00:00Z"));
        BehaviourHistory history = new BehaviourHistory(
                "DEV001",
                0,
                0,
                2,
                Map.of());

        SeverityScore baseScore = severityScoringService.score(event, history);
        SeverityScore escalatedScore = feedbackEscalationService.apply(baseScore, history);
        RecommendationTemplate recommendation =
                recommendationTemplateService.getTemplate(event.vulnerabilityType());

        return new DemoResponse(
                event,
                history,
                baseScore,
                escalatedScore,
                recommendation,
                "String query = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";",
                "SQL query concatenates untrusted user input. An attacker can alter the query.",
                "PreparedStatement statement = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
                        + "statement.setString(1, userId);",
                sampleFile.toString(),
                "vscode://file/" + sampleFile.toString().replace("\\", "/").replace(" ", "%20")
                        + ":5:1",
                List.of(
                        new FileFinding(
                                "SQL_INJECTION",
                                sampleFile.toString(),
                                5,
                                "SQL query concatenates untrusted user input.",
                                "String query = \"SELECT * FROM users WHERE id = '\" + \"userId\" + \"'\";",
                                "PreparedStatement statement = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
                                        + "statement.setString(1, userId);",
                                vscodeUri(sampleFile, 5)),
                        new FileFinding(
                                "XSS",
                                xssFile.toString(),
                                5,
                                "Unescaped user input is rendered as HTML and can execute attacker-controlled script.",
                                "return \"<div>\" + displayName + \"</div>\";",
                                "return \"<div>\" + HtmlUtils.htmlEscape(displayName) + \"</div>\";",
                                vscodeUri(xssFile, 5)),
                        new FileFinding(
                                "HARDCODED_SECRET",
                                secretFile.toString(),
                                5,
                                "A credential is embedded in source code and may be exposed through version control.",
                                "private final String apiKey = \"sk-demo-123456\";",
                                "private final String apiKey = System.getenv(\"API_KEY\");",
                                vscodeUri(secretFile, 5))));
    }

    private String vscodeUri(Path file, int line) {
        return "vscode://file/" + file.toString().replace("\\", "/").replace(" ", "%20")
                + ":" + line + ":1";
    }

    public record DemoResponse(
            SecurityEvent event,
            BehaviourHistory behaviourHistory,
            SeverityScore baseScore,
            SeverityScore escalatedScore,
            RecommendationTemplate recommendation,
            String vulnerableCode,
            String errorMessage,
            String correctedCode,
            String sourceFilePath,
            String vscodeFileUri,
            List<FileFinding> findings
    ) {
    }

    public record FileFinding(
            String vulnerability,
            String filePath,
            int lineNumber,
            String errorMessage,
            String vulnerableCode,
            String correctedCode,
            String vscodeFileUri
    ) {
    }
}
