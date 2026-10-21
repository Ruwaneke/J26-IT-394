package com.sentinel.feedback.coach;

import com.sentinel.feedback.decision.Channel;
import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Alert-fatigue rules as a pure function of recent interruptions. They only ever lower
 * the delivery channel; the level and the warning itself are untouched, and exempt
 * findings (hardcoded secrets, CRITICAL) are never quietened.
 */
@Component
public class FatiguePolicy {

    private final PolicyProperties.Fatigue fatigue;

    public FatiguePolicy(PolicyProperties policy) {
        this.fatigue = policy.fatigue();
    }

    /**
     * @param interruptionsLastHour   interruptive notices already delivered to this developer in the last hour
     * @param lastSameIssueInterrupt  when this CWE in this file last interrupted the developer, or null
     */
    public Delivery apply(Channel channel, boolean exempt, long interruptionsLastHour,
                          Instant lastSameIssueInterrupt, Instant now) {
        if (!channel.interruptive()) {
            return new Delivery(channel, List.of());
        }
        boolean inCooldown = lastSameIssueInterrupt != null
                && Duration.between(lastSameIssueInterrupt, now).toMinutes() < fatigue.cooldownMinutes();
        boolean overBudget = interruptionsLastHour >= fatigue.interruptsPerHour();

        if (exempt) {
            return inCooldown || overBudget
                    ? new Delivery(channel, List.of("Shown as a " + channel.label()
                    + " despite fatigue limits: hardcoded secrets and critical findings are never quietened"))
                    : new Delivery(channel, List.of());
        }
        if (inCooldown) {
            long minutes = Duration.between(lastSameIssueInterrupt, now).toMinutes();
            String ago = minutes < 1 ? "less than a minute ago" : minutes + (minutes == 1 ? " minute ago" : " minutes ago");
            return new Delivery(Channel.INLINE, List.of(String.format(Locale.ROOT,
                    "Shown as an inline hint only: the same issue in this file already raised a popup %s (cooldown %d minutes)",
                    ago, fatigue.cooldownMinutes())));
        }
        if (overBudget) {
            return new Delivery(Channel.INLINE_HOVER, List.of(String.format(Locale.ROOT,
                    "Lowered from %s to %s: you already had %d interruptions in the last hour (budget %d)",
                    channel.label(), Channel.INLINE_HOVER.label(), interruptionsLastHour,
                    fatigue.interruptsPerHour())));
        }
        return new Delivery(channel, List.of());
    }

    public record Delivery(Channel channel, List<String> notes) {
    }
}
