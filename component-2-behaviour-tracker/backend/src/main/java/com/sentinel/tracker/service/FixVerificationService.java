package com.sentinel.tracker.service;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.FixVerificationStatus;

import java.time.LocalDateTime;

/**
 * Decides whether a developer's FIX claim on a security event is verified.
 *
 * <p>Called by {@link DeveloperInteractionService#createInteraction} for every FIX action,
 * inside its transaction and while the event's row lock is held, so implementations must
 * answer from data already available and never call out to slow services.
 *
 * <p>Until C1 reports whether a finding is still present after a fix, the only
 * implementation returns {@link FixVerificationStatus#CLAIMED}. Tests replace it with
 * controlled mock results.
 */
public interface FixVerificationService {

    /**
     * The verification result for a FIX claimed on {@code event} at {@code claimedAt}.
     * A null result is stored as {@link FixVerificationStatus#CLAIMED}.
     */
    FixVerificationStatus verifyFix(SecurityEvent event, LocalDateTime claimedAt);
}
