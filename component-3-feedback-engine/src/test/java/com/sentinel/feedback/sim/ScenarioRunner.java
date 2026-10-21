package com.sentinel.feedback.sim;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.feedback.decision.DecisionService;
import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackDecision;
import com.sentinel.feedback.decision.FeedbackEvent;
import com.sentinel.feedback.decision.LevelMapper;
import com.sentinel.feedback.decision.ScoringService;
import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.recommendation.RecommendationTemplateService;
import com.sentinel.feedback.skill.InMemorySkillStore;
import com.sentinel.feedback.skill.SkillModelService;
import com.sentinel.feedback.testutil.MutableClock;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;

/**
 * Replays a scenario's timeline into a fresh skill model, then asks the engine for a
 * decision. Variants: V0 generic (no history), V1 history counters only (no skill
 * events, so mastery stays at its initial value), V2 counters plus the skill model.
 */
final class ScenarioRunner {

    static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");

    enum Variant { V0, V1, V2 }

    record Result(int level, double score, double mastery) {
    }

    private ScenarioRunner() {
    }

    static List<Scenario> load() {
        try (InputStream in = ScenarioRunner.class.getResourceAsStream("/scenarios/scenarios.json")) {
            return new ObjectMapper().readValue(in, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static Result run(Scenario scenario, Variant variant, PolicyProperties policy) {
        MutableClock clock = new MutableClock(NOW);
        SkillModelService skills = new SkillModelService(policy, new InMemorySkillStore(), clock);
        String devHash = "sim-" + scenario.id();

        if (variant == Variant.V2) {
            scenario.skillEvents().stream()
                    .sorted(Comparator.comparingInt(Scenario.SkillEventInput::daysAgo).reversed())
                    .forEach(event -> {
                        clock.set(NOW.minus(Duration.ofDays(event.daysAgo())));
                        skills.record(devHash, scenario.event().cwe(), event.type());
                    });
            clock.set(NOW);
        }

        Scenario.HistoryInput h = scenario.history();
        DeveloperHistory history = variant == Variant.V0
                ? new DeveloperHistory(devHash, 0, 0, 0, 0, null)
                : new DeveloperHistory(devHash, h.repeats30d(), h.ignored30d(), h.fixed30d(),
                h.reopened30d(), h.lastSimilarDaysAgo());

        DecisionService decisions = new DecisionService(policy, skills, new ScoringService(policy),
                new LevelMapper(policy), new RecommendationTemplateService());
        FeedbackDecision decision = decisions.decide(new FeedbackEvent("e-" + scenario.id(),
                scenario.event().cwe(), scenario.event().severity(), "java", 1, null), history);
        return new Result(decision.level(), decision.score(), decision.mastery());
    }

    static long correct(List<Scenario> scenarios, Predicate<Scenario> filter, Variant variant,
                        PolicyProperties policy) {
        return scenarios.stream()
                .filter(filter)
                .filter(s -> run(s, variant, policy).level() == s.expectedLevel())
                .count();
    }
}
