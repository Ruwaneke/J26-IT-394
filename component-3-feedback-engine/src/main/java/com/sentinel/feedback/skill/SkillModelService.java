package com.sentinel.feedback.skill;

import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Per-developer, per-CWE mastery model. {@link #update} and {@link #decay} are pure
 * functions of the policy; the remaining methods add storage around them.
 */
@Service
public class SkillModelService {

    private static final double SECONDS_PER_DAY = 86_400.0;

    private final PolicyProperties.Mastery params;
    private final SkillStore store;
    private final Clock clock;

    public SkillModelService(PolicyProperties policy, SkillStore store, Clock clock) {
        this.params = policy.mastery();
        this.store = store;
        this.clock = clock;
    }

    /** Applies one event: fixes move M toward 1, everything else shrinks it toward 0. */
    public double update(double mastery, SkillEventType event) {
        double updated = switch (event) {
            case FIX -> mastery + params.fixGain() * (1 - mastery);
            case IGNORE -> mastery - params.ignoreLoss() * mastery;
            case REPEAT -> mastery - params.repeatLoss() * mastery;
            case REOPEN -> mastery - params.reopenLoss() * mastery;
        };
        return clamp(updated);
    }

    /** Fades M toward the initial "unknown" value with the configured half-life. */
    public double decay(double mastery, Duration elapsed) {
        if (elapsed.isNegative() || elapsed.isZero()) {
            return mastery;
        }
        double days = elapsed.getSeconds() / SECONDS_PER_DAY;
        double factor = Math.pow(2, -days / params.halfLifeDays());
        return clamp(params.initial() + (mastery - params.initial()) * factor);
    }

    public double currentMastery(String devHash, String cweId) {
        return current(devHash, cweId).mastery();
    }

    public List<SkillState> currentSkills(String devHash) {
        return store.findAll(devHash).stream()
                .map(state -> decayed(state, clock.instant()))
                .toList();
    }

    public SkillState record(String devHash, String cweId, SkillEventType event) {
        Instant now = clock.instant();
        SkillState current = current(devHash, cweId);
        SkillState updated = new SkillState(
                devHash,
                cweId,
                update(current.mastery(), event),
                current.eventsCount() + 1,
                now);
        store.save(updated, new SkillEventEntry(devHash, cweId, event, current.mastery(),
                updated.mastery(), now));
        return updated;
    }

    private SkillState current(String devHash, String cweId) {
        return store.find(devHash, cweId)
                .map(state -> decayed(state, clock.instant()))
                .orElseGet(() -> new SkillState(devHash, cweId, params.initial(), 0, null));
    }

    private SkillState decayed(SkillState state, Instant now) {
        if (state.lastEventAt() == null) {
            return state;
        }
        double mastery = decay(state.mastery(), Duration.between(state.lastEventAt(), now));
        return new SkillState(state.devHash(), state.cweId(), mastery, state.eventsCount(),
                state.lastEventAt());
    }

    private double clamp(double value) {
        return Math.max(0.0, Math.min(1.0, value));
    }
}
