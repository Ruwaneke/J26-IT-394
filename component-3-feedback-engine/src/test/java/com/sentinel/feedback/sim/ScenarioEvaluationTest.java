package com.sentinel.feedback.sim;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.feedback.decision.DecisionService;
import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackEvent;
import com.sentinel.feedback.decision.LevelMapper;
import com.sentinel.feedback.decision.ScoringService;
import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.policy.TestPolicies;
import com.sentinel.feedback.recommendation.RecommendationTemplateService;
import com.sentinel.feedback.skill.InMemorySkillStore;
import com.sentinel.feedback.skill.SkillEventType;
import com.sentinel.feedback.skill.SkillModelService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Replays the rubric-labelled scenarios (tools/generate_scenarios.py) against three
 * engine variants and writes target/scenario-report.md:
 * V0 generic (no history), V1 history counters only (mastery fixed at the initial
 * value), V2 counters plus the skill model.
 */
class ScenarioEvaluationTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final PolicyProperties POLICY = TestPolicies.defaults();

    private static List<Scenario> scenarios;

    @BeforeAll
    static void loadScenarios() throws IOException {
        try (InputStream in = ScenarioEvaluationTest.class.getResourceAsStream("/scenarios/scenarios.json")) {
            scenarios = new ObjectMapper().readValue(in, new TypeReference<>() {
            });
        }
    }

    @Test
    void scenarioSetIsWellFormed() {
        assertEquals(48, scenarios.size());
        Set<String> ids = scenarios.stream().map(Scenario::id).collect(Collectors.toSet());
        assertEquals(scenarios.size(), ids.size(), "scenario ids must be unique");
        assertTrue(scenarios.stream().allMatch(s -> s.set().equals("tuning") || s.set().equals("heldout")));
        assertTrue(scenarios.stream().allMatch(s -> s.expectedLevel() >= 1 && s.expectedLevel() <= 4));
    }

    @Test
    void writesEvaluationReport() throws IOException {
        List<Row> rows = scenarios.stream()
                .map(s -> new Row(s, run(s, Variant.V0), run(s, Variant.V1), run(s, Variant.V2)))
                .toList();

        String report = report(rows);
        Path out = Path.of("target", "scenario-report.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, report);
        System.out.println(report);
    }

    private Result run(Scenario scenario, Variant variant) {
        MutableClock clock = new MutableClock(NOW);
        SkillModelService skills = new SkillModelService(POLICY, new InMemorySkillStore(), clock);
        String devHash = "sim-" + scenario.id();

        if (variant == Variant.V2) {
            scenario.skillEvents().stream()
                    .sorted(Comparator.comparingInt(SkillEventInput::daysAgo).reversed())
                    .forEach(event -> {
                        clock.set(NOW.minus(Duration.ofDays(event.daysAgo())));
                        skills.record(devHash, scenario.event().cwe(), event.type());
                    });
            clock.set(NOW);
        }

        HistoryInput h = scenario.history();
        DeveloperHistory history = variant == Variant.V0
                ? new DeveloperHistory(devHash, 0, 0, 0, 0, null)
                : new DeveloperHistory(devHash, h.repeats30d(), h.ignored30d(), h.fixed30d(),
                h.reopened30d(), h.lastSimilarDaysAgo());

        DecisionService decisions = new DecisionService(POLICY, skills, new ScoringService(POLICY),
                new LevelMapper(POLICY), new RecommendationTemplateService());
        var decision = decisions.decide(new FeedbackEvent("e-" + scenario.id(), scenario.event().cwe(),
                scenario.event().severity(), "java", 1, null), history);
        return new Result(decision.level(), decision.score(), decision.mastery());
    }

    private String report(List<Row> rows) {
        StringBuilder md = new StringBuilder();
        md.append("# Escalation correctness (policy ").append(POLICY.version()).append(")\n\n");
        md.append("| Set | n | V0 generic | V1 counters | V2 counters + skill model |\n");
        md.append("|---|---|---|---|---|\n");
        for (String set : List.of("tuning", "heldout", "all")) {
            List<Row> subset = rows.stream()
                    .filter(r -> set.equals("all") || r.scenario().set().equals(set))
                    .toList();
            md.append(String.format(Locale.ROOT, "| %s | %d | %s | %s | %s |%n", set, subset.size(),
                    pct(subset, Variant.V0), pct(subset, Variant.V1), pct(subset, Variant.V2)));
        }

        md.append("\n## V2 disagreements with the rubric\n\n");
        md.append("| Id | Set | Situation | Severity | Expected | V2 | Score | Mastery | V1 |\n");
        md.append("|---|---|---|---|---|---|---|---|---|\n");
        for (Row r : rows) {
            if (r.v2().level() != r.scenario().expectedLevel()) {
                md.append(String.format(Locale.ROOT, "| %s | %s | %s | %s | L%d | L%d | %.2f | %.2f | L%d |%n",
                        r.scenario().id(), r.scenario().set(), r.scenario().situation(),
                        r.scenario().event().severity(), r.scenario().expectedLevel(), r.v2().level(),
                        r.v2().score(), r.v2().mastery(), r.v1().level()));
            }
        }

        md.append("\n## Where the skill model changed the decision (V1 -> V2)\n\n");
        md.append("| Id | Situation | Expected | V1 | V2 | Mastery |\n|---|---|---|---|---|---|\n");
        for (Row r : rows) {
            if (r.v1().level() != r.v2().level()) {
                md.append(String.format(Locale.ROOT, "| %s | %s | L%d | L%d | L%d | %.2f |%n",
                        r.scenario().id(), r.scenario().situation(), r.scenario().expectedLevel(),
                        r.v1().level(), r.v2().level(), r.v2().mastery()));
            }
        }
        return md.toString();
    }

    private String pct(List<Row> rows, Variant variant) {
        long correct = rows.stream().filter(r -> r.level(variant) == r.scenario().expectedLevel()).count();
        return String.format(Locale.ROOT, "%d/%d (%.0f%%)", correct, rows.size(),
                100.0 * correct / rows.size());
    }

    enum Variant { V0, V1, V2 }

    record Result(int level, double score, double mastery) {
    }

    record Row(Scenario scenario, Result v0, Result v1, Result v2) {
        int level(Variant variant) {
            return switch (variant) {
                case V0 -> v0.level();
                case V1 -> v1.level();
                case V2 -> v2.level();
            };
        }
    }

    record Scenario(String id, String set, String situation, String description, EventInput event,
                    HistoryInput history, List<SkillEventInput> skillEvents, int expectedLevel,
                    String rationale) {
        Scenario {
            skillEvents = skillEvents == null ? List.of() : new ArrayList<>(skillEvents);
        }
    }

    record EventInput(String cwe, Severity severity) {
    }

    record HistoryInput(int repeats30d, int ignored30d, int fixed30d, int reopened30d,
                        Integer lastSimilarDaysAgo) {
    }

    record SkillEventInput(SkillEventType type, int daysAgo) {
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void set(Instant instant) {
            now = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
