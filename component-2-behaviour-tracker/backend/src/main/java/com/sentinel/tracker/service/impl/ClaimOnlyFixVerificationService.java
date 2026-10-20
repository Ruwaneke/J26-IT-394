package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.FixVerificationStatus;
import com.sentinel.tracker.service.FixVerificationService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Implementation of {@link FixVerificationService} used until a verification source exists.
 *
 * C2 has no evidence about the source code: C1 sends FIX when the developer uses the Fix code
 * action, not after re-scanning the file. Every FIX is therefore recorded as CLAIMED, and is
 * never reported as VERIFIED without evidence.
 */
@Service
public class ClaimOnlyFixVerificationService implements FixVerificationService {

    @Override
    public FixVerificationStatus verifyFix(SecurityEvent event, LocalDateTime claimedAt) {
        return FixVerificationStatus.CLAIMED;
    }
}
