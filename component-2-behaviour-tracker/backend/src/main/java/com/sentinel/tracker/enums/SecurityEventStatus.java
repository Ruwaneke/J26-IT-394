package com.sentinel.tracker.enums;

/**
 * Lifecycle status of a security event.
 * Represents the progression from detection through resolution.
 */
public enum SecurityEventStatus {
    DETECTED,
    OPENED,
    IGNORED,
    REOPENED,
    FIXED
}
