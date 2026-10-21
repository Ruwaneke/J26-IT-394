package com.sentinel.feedback.coach;

import com.sentinel.feedback.decision.Channel;
import com.sentinel.feedback.policy.TestPolicies;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FatiguePolicyTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");

    private final FatiguePolicy fatigue = new FatiguePolicy(TestPolicies.defaults());

    @Test
    void thirdInterruptionIsAllowedFourthIsDowngraded() {
        assertEquals(Channel.TOAST_PANEL, fatigue.apply(Channel.TOAST_PANEL, false, 2, null, NOW).channel());

        FatiguePolicy.Delivery fourth = fatigue.apply(Channel.TOAST_PANEL, false, 3, null, NOW);
        assertEquals(Channel.INLINE_HOVER, fourth.channel());
        assertTrue(fourth.notes().get(0).contains("3 interruptions in the last hour"));
    }

    @Test
    void cooldownBlocksRepeatPopupWithinTenMinutes() {
        assertEquals(Channel.INLINE, fatigue.apply(Channel.PANEL_ACK, false, 0,
                NOW.minus(Duration.ofMinutes(9)), NOW).channel());
        assertEquals(Channel.PANEL_ACK, fatigue.apply(Channel.PANEL_ACK, false, 0,
                NOW.minus(Duration.ofMinutes(11)), NOW).channel());
    }

    @Test
    void exemptFindingsAreNeverQuietened() {
        FatiguePolicy.Delivery overBudget = fatigue.apply(Channel.TOAST_PANEL, true, 10,
                NOW.minus(Duration.ofMinutes(1)), NOW);
        assertEquals(Channel.TOAST_PANEL, overBudget.channel());
        assertTrue(overBudget.notes().get(0).contains("never quietened"));

        assertTrue(fatigue.apply(Channel.TOAST_PANEL, true, 0, null, NOW).notes().isEmpty());
    }

    @Test
    void quietChannelsAreLeftAlone() {
        FatiguePolicy.Delivery delivery = fatigue.apply(Channel.INLINE_HOVER, false, 99, NOW, NOW);
        assertEquals(Channel.INLINE_HOVER, delivery.channel());
        assertTrue(delivery.notes().isEmpty());
    }
}
