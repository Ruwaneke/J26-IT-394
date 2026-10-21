package com.sentinel.feedback.sim;

import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Replays the rubric-labelled scenarios against V0 (generic), V1 (counters only) and
 * V2 (counters + skill model) for the plan's starting policy and the shipped policy,
 * runs a +/-25% sensitivity check on the mastery parameters, and writes
 * target/scenario-report.md.
 */
class ScenarioEvaluationTest {

    private static final PolicyProperties PLAN = TestPolicies.defaults();
    private static final PolicyProperties SHIPPED = TestPolicies.shipped();

    private static List<Scenario> scenarios;

    @BeforeAll
    static void loadScenarios() {
        scenarios = ScenarioRunner.load();
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
    void skillModelDoesNotLoseToSimplerBaselinesOnHeldOutScenarios() {
        long v0 = ScenarioRunner.correct(scenarios, Scenario::isHeldOut, ScenarioRunner.Variant.V0, SHIPPED);
        long v1 = ScenarioRunner.correct(scenarios, Scenario::isHeldOut, ScenarioRunner.Variant.V1, SHIPPED);
        long v2 = ScenarioRunner.correct(scenarios, Scenario::isHeldOut, ScenarioRunner.Variant.V2, SHIPPED);

        assertTrue(v1 >= v0, "counters should not be worse than generic feedback");
        assertTrue(v2 >= v1, "the skill model should not be worse than counters alone");
    }

    @Test
    void writesEvaluationReport() throws IOException {
        StringBuilder md = new StringBuilder("# Escalation correctness\n\n");
        md.append("| Policy | Set | n | V0 generic | V1 counters | V2 counters + skill model |\n");
        md.append("|---|---|---|---|---|---|\n");
        for (PolicyProperties policy : List.of(PLAN, SHIPPED)) {
            List<Row> rows = rows(policy);
            for (String set : List.of("tuning", "heldout", "all")) {
                List<Row> subset = rows.stream()
                        .filter(r -> set.equals("all") || r.scenario().set().equals(set))
                        .toList();
                md.append(String.format(Locale.ROOT, "| %s | %s | %d | %s | %s | %s |%n",
                        policy.version(), set, subset.size(),
                        pct(subset, ScenarioRunner.Variant.V0), pct(subset, ScenarioRunner.Variant.V1),
                        pct(subset, ScenarioRunner.Variant.V2)));
            }
        }

        List<Row> shipped = rows(SHIPPED);
        md.append("\n## V2 disagreements with the rubric (policy ").append(SHIPPED.version()).append(")\n\n");
        md.append("| Id | Set | Situation | Severity | Expected | V2 | Score | Mastery | V1 |\n");
        md.append("|---|---|---|---|---|---|---|---|---|\n");
        for (Row r : shipped) {
            if (r.v2().level() != r.scenario().expectedLevel()) {
                md.append(String.format(Locale.ROOT, "| %s | %s | %s | %s | L%d | L%d | %.2f | %.2f | L%d |%n",
                        r.scenario().id(), r.scenario().set(), r.scenario().situation(),
                        r.scenario().event().severity(), r.scenario().expectedLevel(), r.v2().level(),
                        r.v2().score(), r.v2().mastery(), r.v1().level()));
            }
        }

        md.append("\n## Where the skill model changed the decision (V1 -> V2, policy ")
                .append(SHIPPED.version()).append(")\n\n");
        md.append("| Id | Situation | Expected | V1 | V2 | Mastery |\n|---|---|---|---|---|---|\n");
        for (Row r : shipped) {
            if (r.v1().level() != r.v2().level()) {
                md.append(String.format(Locale.ROOT, "| %s | %s | L%d | L%d | L%d | %.2f |%n",
                        r.scenario().id(), r.scenario().situation(), r.scenario().expectedLevel(),
                        r.v1().level(), r.v2().level(), r.v2().mastery()));
            }
        }

        md.append(sensitivity(shipped));

        Path out = Path.of("target", "scenario-report.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, md);
        System.out.println(md);
    }

    /** Varies each mastery parameter by -25% and +25% and counts unchanged V2 decisions. */
    private String sensitivity(List<Row> baseline) {
        StringBuilder md = new StringBuilder("\n## Sensitivity of V2 decisions to mastery parameters (+/-25%)\n\n");
        md.append("| Parameter | -25%: unchanged / accuracy | +25%: unchanged / accuracy |\n|---|---|---|\n");
        List<Param> params = List.of(
                new Param("fix-gain", f -> m -> mastery(m, f * m.fixGain(), m.ignoreLoss(), m.repeatLoss(), m.reopenLoss(), m.halfLifeDays())),
                new Param("ignore-loss", f -> m -> mastery(m, m.fixGain(), f * m.ignoreLoss(), m.repeatLoss(), m.reopenLoss(), m.halfLifeDays())),
                new Param("repeat-loss", f -> m -> mastery(m, m.fixGain(), m.ignoreLoss(), f * m.repeatLoss(), m.reopenLoss(), m.halfLifeDays())),
                new Param("reopen-loss", f -> m -> mastery(m, m.fixGain(), m.ignoreLoss(), m.repeatLoss(), f * m.reopenLoss(), m.halfLifeDays())),
                new Param("half-life-days", f -> m -> mastery(m, m.fixGain(), m.ignoreLoss(), m.repeatLoss(), m.reopenLoss(), f * m.halfLifeDays())));
        for (Param param : params) {
            md.append("| ").append(param.name());
            for (double factor : new double[] {0.75, 1.25}) {
                PolicyProperties varied = withMastery(SHIPPED, param.change().apply(factor).apply(SHIPPED.mastery()));
                long unchanged = 0;
                long correct = 0;
                for (Row r : baseline) {
                    int level = ScenarioRunner.run(r.scenario(), ScenarioRunner.Variant.V2, varied).level();
                    unchanged += level == r.v2().level() ? 1 : 0;
                    correct += level == r.scenario().expectedLevel() ? 1 : 0;
                }
                md.append(String.format(Locale.ROOT, " | %d/%d / %d/%d", unchanged, baseline.size(),
                        correct, baseline.size()));
            }
            md.append(" |\n");
        }
        return md.toString();
    }

    private static PolicyProperties.Mastery mastery(PolicyProperties.Mastery m, double fixGain, double ignoreLoss,
                                                    double repeatLoss, double reopenLoss, double halfLifeDays) {
        return new PolicyProperties.Mastery(m.initial(), fixGain, ignoreLoss, repeatLoss, reopenLoss,
                halfLifeDays, m.masteredThreshold());
    }

    private static PolicyProperties withMastery(PolicyProperties p, PolicyProperties.Mastery mastery) {
        return new PolicyProperties(p.version(), p.weights(), p.pressureSaturation(), p.reopensCountAsRepeats(),
                p.recency(), p.levels(), mastery, p.overrides(), p.fatigue());
    }

    private List<Row> rows(PolicyProperties policy) {
        return scenarios.stream()
                .map(s -> new Row(s,
                        ScenarioRunner.run(s, ScenarioRunner.Variant.V0, policy),
                        ScenarioRunner.run(s, ScenarioRunner.Variant.V1, policy),
                        ScenarioRunner.run(s, ScenarioRunner.Variant.V2, policy)))
                .toList();
    }

    private String pct(List<Row> rows, ScenarioRunner.Variant variant) {
        long correct = rows.stream().filter(r -> r.level(variant) == r.scenario().expectedLevel()).count();
        return String.format(Locale.ROOT, "%d/%d (%.0f%%)", correct, rows.size(),
                100.0 * correct / rows.size());
    }

    record Param(String name, java.util.function.DoubleFunction<UnaryOperator<PolicyProperties.Mastery>> change) {
    }

    record Row(Scenario scenario, ScenarioRunner.Result v0, ScenarioRunner.Result v1,
               ScenarioRunner.Result v2) {
        int level(ScenarioRunner.Variant variant) {
            return switch (variant) {
                case V0 -> v0.level();
                case V1 -> v1.level();
                case V2 -> v2.level();
            };
        }
    }
}
