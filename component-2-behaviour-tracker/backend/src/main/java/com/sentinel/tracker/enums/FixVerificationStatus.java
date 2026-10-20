package com.sentinel.tracker.enums;

/**
 * Whether a developer's FIX action is backed by evidence that the vulnerability is gone.
 *
 * <p>A FIX action is a <em>claim</em>: C1 sends it when the developer uses the Fix code action,
 * which only shows the secure example. The event moves to FIXED either way; this value says
 * whether that fix was verified. Set only on FIX interactions, null on all others.
 */
public enum FixVerificationStatus {
    /** The developer reported a fix; nothing has confirmed it. */
    CLAIMED,
    /** A verification source confirmed the vulnerability is no longer present. */
    VERIFIED,
    /** A verification source found the vulnerability still present after the claimed fix. */
    STILL_VULNERABLE
}
