package com.sentinel.feedback.sim;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.policy.TestPolicies;
import com.sentinel.feedback.skill.SkillEventType;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Checks the engine against expected levels supplied from outside (hand calculations,
 * a spreadsheet, or levels chosen by supervisors). Add rows to
 * src/test/resources/validation/external-results.csv and run `mvn test`; the result is
 * written to target/external-validation-report.md. Mismatches are reported, not failed,
 * so the file can hold genuine disagreements.
 */
class ExternalValidationTest {

    private static final PolicyProperties POLICY = TestPolicies.shipped();

    @Test
    void comparesEngineWithExternalResults() throws IOException {
        List<Scenario> cases = load();
        assertFalse(cases.isEmpty(), "external-results.csv has no rows");

        StringBuilder md = new StringBuilder("# External validation (policy ")
                .append(POLICY.version()).append(")\n\n")
                .append("| Id | CWE | Severity | Expected | Engine | Score | Match |\n")
                .append("|---|---|---|---|---|---|---|\n");
        int matches = 0;
        for (Scenario c : cases) {
            ScenarioRunner.Result result = ScenarioRunner.run(c, ScenarioRunner.Variant.V2, POLICY);
            boolean match = result.level() == c.expectedLevel();
            matches += match ? 1 : 0;
            md.append(String.format(Locale.ROOT, "| %s | %s | %s | L%d | L%d | %.2f | %s |%n",
                    c.id(), c.event().cwe(), c.event().severity(), c.expectedLevel(), result.level(),
                    result.score(), match ? "yes" : "**NO**"));
        }
        md.insert(md.indexOf("\n\n") + 2, String.format(Locale.ROOT, "Matches: **%d / %d** (%.0f%%)%n%n",
                matches, cases.size(), 100.0 * matches / cases.size()));

        Path out = Path.of("target", "external-validation-report.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, md);
        System.out.println(md);
    }

    /** Past actions are replayed in order (oldest first) at the time of the decision. */
    private static List<Scenario> load() throws IOException {
        List<Scenario> cases = new ArrayList<>();
        try (InputStream in = ExternalValidationTest.class.getResourceAsStream("/validation/external-results.csv");
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String header = reader.readLine();
            String line;
            int lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                String[] f = line.split(",", -1);
                if (f.length != 10) {
                    throw new IllegalArgumentException("Line " + lineNumber + " needs 10 columns like the header: " + header);
                }
                List<Scenario.SkillEventInput> actions = Arrays.stream(f[8].trim().split("\\s+"))
                        .filter(s -> !s.isEmpty())
                        .map(s -> new Scenario.SkillEventInput(SkillEventType.valueOf(s.toUpperCase(Locale.ROOT)), 0))
                        .toList();
                cases.add(new Scenario(
                        f[0].trim(), "external", "external", "",
                        new Scenario.EventInput(f[1].trim(), Severity.valueOf(f[2].trim().toUpperCase(Locale.ROOT))),
                        new Scenario.HistoryInput(num(f[3]), num(f[4]), num(f[5]), num(f[6]),
                                f[7].isBlank() ? null : num(f[7])),
                        actions,
                        num(f[9]),
                        ""));
            }
        }
        return cases;
    }

    private static int num(String value) {
        return Integer.parseInt(value.trim());
    }
}
