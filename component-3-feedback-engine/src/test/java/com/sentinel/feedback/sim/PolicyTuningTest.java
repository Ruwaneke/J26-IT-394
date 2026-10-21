package com.sentinel.feedback.sim;

import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Grid search over policy parameters using ONLY the tuning scenarios. Held-out
 * scenarios are never read here, so the held-out accuracy in ScenarioEvaluationTest
 * stays an honest estimate. Writes target/tuning-report.md.
 */
class PolicyTuningTest {

    private static final double[] L2 = {25, 27.5, 30};
    private static final double[] L3 = {50, 55};
    private static final double[] L4 = {75, 77.5, 80};
    private static final double[] MASTERED = {0.60, 0.65, 0.70, 0.75};
    private static final boolean[] REOPENS = {false, true};

    @Test
    void searchesPolicyGridOnTuningScenarios() throws IOException {
        List<Scenario> tuning = ScenarioRunner.load().stream().filter(s -> !s.isHeldOut()).toList();
        PolicyProperties base = TestPolicies.defaults();

        List<Candidate> candidates = new ArrayList<>();
        for (double l2 : L2) {
            for (double l3 : L3) {
                for (double l4 : L4) {
                    for (double mastered : MASTERED) {
                        for (boolean reopens : REOPENS) {
                            PolicyProperties policy = variant(base, l2, l3, l4, mastered, reopens);
                            long correct = ScenarioRunner.correct(tuning, s -> true,
                                    ScenarioRunner.Variant.V2, policy);
                            candidates.add(new Candidate(l2, l3, l4, mastered, reopens, correct,
                                    changes(base, policy)));
                        }
                    }
                }
            }
        }
        // Most correct first; among ties prefer the fewest departures from policy 1.0.0.
        candidates.sort(Comparator.comparingLong(Candidate::correct).reversed()
                .thenComparingInt(Candidate::changes));

        StringBuilder md = new StringBuilder("# Policy tuning (tuning set only, n=")
                .append(tuning.size()).append(")\n\n")
                .append("| Rank | L2 | L3 | L4 | Mastered | Reopens as repeats | Correct | Params changed |\n")
                .append("|---|---|---|---|---|---|---|---|\n");
        for (int i = 0; i < Math.min(15, candidates.size()); i++) {
            Candidate c = candidates.get(i);
            md.append(String.format(Locale.ROOT, "| %d | %.1f | %.1f | %.1f | %.2f | %s | %d/%d | %d |%n",
                    i + 1, c.l2(), c.l3(), c.l4(), c.mastered(), c.reopens(), c.correct(),
                    tuning.size(), c.changes()));
        }
        Path out = Path.of("target", "tuning-report.md");
        Files.createDirectories(out.getParent());
        Files.writeString(out, md);
        System.out.println(md);
    }

    static PolicyProperties variant(PolicyProperties base, double l2, double l3, double l4,
                                    double mastered, boolean reopens) {
        PolicyProperties.Mastery m = base.mastery();
        return new PolicyProperties(base.version(), base.weights(), base.pressureSaturation(), reopens,
                base.recency(), new PolicyProperties.Levels(l2, l3, l4),
                new PolicyProperties.Mastery(m.initial(), m.fixGain(), m.ignoreLoss(), m.repeatLoss(),
                        m.reopenLoss(), m.halfLifeDays(), mastered),
                base.overrides());
    }

    private static int changes(PolicyProperties base, PolicyProperties p) {
        int n = 0;
        n += base.levels().l2() != p.levels().l2() ? 1 : 0;
        n += base.levels().l3() != p.levels().l3() ? 1 : 0;
        n += base.levels().l4() != p.levels().l4() ? 1 : 0;
        n += base.mastery().masteredThreshold() != p.mastery().masteredThreshold() ? 1 : 0;
        n += base.reopensCountAsRepeats() != p.reopensCountAsRepeats() ? 1 : 0;
        return n;
    }

    record Candidate(double l2, double l3, double l4, double mastered, boolean reopens, long correct,
                     int changes) {
    }
}
