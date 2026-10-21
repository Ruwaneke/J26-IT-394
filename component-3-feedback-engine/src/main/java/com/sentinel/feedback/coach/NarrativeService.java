package com.sentinel.feedback.coach;

import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackDecision;
import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Plain-language "Why this level?" narrative built only from the decision's own facts.
 * This is the static fallback; Plan C will let an LLM rephrase it, checked against the
 * same numbers.
 */
@Service
public class NarrativeService {

    private final PolicyProperties policy;

    public NarrativeService(PolicyProperties policy) {
        this.policy = policy;
    }

    public String build(FeedbackDecision decision, VulnerabilityType type, Severity severity,
                        DeveloperHistory history, List<String> deliveryNotes) {
        List<String> sentences = new ArrayList<>();
        sentences.add(String.format(Locale.ROOT, "%s (%s) at %s severity gives %s of the %s points.",
                type.displayName(), type.cweId(), severity, fmt(decision.breakdown().severity()),
                fmt(decision.score())));

        List<String> behaviour = new ArrayList<>();
        if (history.repeats30d() > 0) {
            behaviour.add("it came back " + times(history.repeats30d()) + " this month");
        }
        if (history.ignored30d() > 0) {
            behaviour.add(count(history.ignored30d(), "earlier warning") + " " + (history.ignored30d() == 1 ? "was" : "were") + " ignored");
        }
        if (history.reopened30d() > 0) {
            behaviour.add(count(history.reopened30d(), "fix") + " did not hold");
        }
        if (!behaviour.isEmpty()) {
            sentences.add("Recently, " + String.join(" and ", behaviour) + ".");
        } else if (decision.mastery() >= policy.mastery().masteredThreshold()) {
            sentences.add(String.format(Locale.ROOT, "You have a strong record with this issue (mastery %s).",
                    fmt(decision.mastery())));
        } else {
            sentences.add("There is no recent history of this issue for you.");
        }

        sentences.add("That is why you see L" + decision.level() + " " + decision.levelName() + ".");
        sentences.addAll(decision.adjustments().stream().map(NarrativeService::sentence).toList());
        sentences.addAll(deliveryNotes.stream().map(NarrativeService::sentence).toList());
        return String.join(" ", sentences);
    }

    private static String sentence(String text) {
        return text.endsWith(".") ? text : text + ".";
    }

    private static String times(int n) {
        return n == 1 ? "once" : n == 2 ? "twice" : n + " times";
    }

    private static String count(int n, String noun) {
        String plural = noun.endsWith("x") ? noun + "es" : noun + "s";
        return n + " " + (n == 1 ? noun : plural);
    }

    private static String fmt(double value) {
        String s = String.format(Locale.ROOT, "%.2f", value);
        return s.replaceAll("\\.?0+$", "");
    }
}
