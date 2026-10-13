package com.sentinel.tracker.enums;

import java.util.EnumSet;
import java.util.Set;

/**
 * Lifecycle status of a security event.
 * Represents the progression from detection through resolution.
 *
 * Allowed transitions:
 * <ul>
 *   <li>DETECTED is only the initial status; no status can return to it.</li>
 *   <li>Any status except FIXED can move to OPENED, FIXED or IGNORED.</li>
 *   <li>FIXED is resolved and can only be REOPENED.</li>
 *   <li>Only FIXED or IGNORED events can be REOPENED.</li>
 * </ul>
 * Staying in the same status is not a transition.
 */
public enum SecurityEventStatus {
    DETECTED,
    OPENED,
    IGNORED,
    REOPENED,
    FIXED;

    /**
     * The statuses this status may change to.
     */
    public Set<SecurityEventStatus> allowedTransitions() {
        return switch (this) {
            case DETECTED, REOPENED -> EnumSet.of(OPENED, FIXED, IGNORED);
            case OPENED -> EnumSet.of(FIXED, IGNORED);
            case IGNORED -> EnumSet.of(OPENED, FIXED, REOPENED);
            case FIXED -> EnumSet.of(REOPENED);
        };
    }

    /**
     * Whether changing from this status to {@code next} is a valid lifecycle transition.
     */
    public boolean canTransitionTo(SecurityEventStatus next) {
        return allowedTransitions().contains(next);
    }
}
