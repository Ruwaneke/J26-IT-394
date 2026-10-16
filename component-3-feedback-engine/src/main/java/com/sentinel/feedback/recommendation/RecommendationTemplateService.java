package com.sentinel.feedback.recommendation;

import com.sentinel.feedback.model.VulnerabilityType;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class RecommendationTemplateService {

    private final Map<VulnerabilityType, RecommendationTemplate> templates =
            Map.ofEntries(
                    Map.entry(VulnerabilityType.SQL_INJECTION, new RecommendationTemplate(
                            "Use parameterized database queries",
                            "Bind user input as query parameters instead of concatenating it into SQL.",
                            "PreparedStatement statement = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");")),
                    Map.entry(VulnerabilityType.XSS, new RecommendationTemplate(
                            "Escape untrusted output",
                            "Encode user-controlled data for its output context and avoid raw HTML insertion.",
                            "element.textContent = untrustedValue;")),
                    Map.entry(VulnerabilityType.HARDCODED_SECRET, new RecommendationTemplate(
                            "Move secrets to secure configuration",
                            "Store credentials in a secret manager or protected environment configuration, never in source code.",
                            "String apiKey = System.getenv(\"API_KEY\");")),
                    Map.entry(VulnerabilityType.COMMAND_INJECTION, new RecommendationTemplate(
                            "Avoid shell interpretation of user input",
                            "Use a process API with a fixed executable and separate, validated arguments.",
                            "new ProcessBuilder(\"git\", \"status\").start();")),
                    Map.entry(VulnerabilityType.PATH_TRAVERSAL, new RecommendationTemplate(
                            "Constrain file access to an allowed directory",
                            "Resolve and normalize paths, then verify the resolved path remains within the intended directory.",
                            "Path safePath = baseDirectory.resolve(input).normalize();")),
                    Map.entry(VulnerabilityType.MISSING_INPUT_VALIDATION, new RecommendationTemplate(
                            "Validate input at the trust boundary",
                            "Apply allowlists, type checks, length limits and range validation before processing input.",
                            "@Valid @RequestBody CreateRequest request")),
                    Map.entry(VulnerabilityType.UNSAFE_DESERIALIZATION, new RecommendationTemplate(
                            "Deserialize only trusted, constrained data",
                            "Use a safe data format and an explicit allowlist of permitted types.",
                            "ObjectMapper mapper = new ObjectMapper();")),
                    Map.entry(VulnerabilityType.WEAK_CRYPTOGRAPHY, new RecommendationTemplate(
                            "Use modern approved cryptography",
                            "Replace obsolete algorithms with current platform-approved algorithms and key sizes.",
                            "MessageDigest.getInstance(\"SHA-256\");")),
                    Map.entry(VulnerabilityType.INSECURE_AUTH, new RecommendationTemplate(
                            "Enforce strong authentication controls",
                            "Use secure password hashing, session protection, authorization checks and appropriate MFA.",
                            "PasswordEncoder encoder = new BCryptPasswordEncoder();")),
                    Map.entry(VulnerabilityType.SENSITIVE_DATA_EXPOSURE, new RecommendationTemplate(
                            "Minimize and protect sensitive data",
                            "Redact secrets from responses and logs, encrypt sensitive data, and expose only required fields.",
                            "return new UserSummary(user.id(), user.displayName());"))
            );

    public RecommendationTemplate getTemplate(VulnerabilityType vulnerabilityType) {
        RecommendationTemplate template = templates.get(vulnerabilityType);
        if (template == null) {
            throw new IllegalArgumentException("No recommendation template for " + vulnerabilityType);
        }
        return template;
    }
}
