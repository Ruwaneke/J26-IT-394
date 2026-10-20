package com.sentinel.tracker.dto;

import com.sentinel.tracker.enums.HistoryIntegrityStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for verifying a security event's lifecycle hash chain.
 */
@Data
@Builder
public class HistoryVerificationResponse {

    private Long securityEventId;
    private HistoryIntegrityStatus status;

    /** Number of history entries found. */
    private int entryCount;

    /** Leading entries written before the hash chain existed (not verifiable). */
    private int unchainedEntryCount;

    /** 1-based position, in id order, of the first entry that fails; null unless BROKEN. */
    private Integer brokenAtEntry;

    /** Id of the first entry that fails; null unless BROKEN or when no entry exists. */
    private Long brokenAtHistoryId;

    /** Why the chain is broken; null unless BROKEN. */
    private String reason;

    private LocalDateTime verifiedAt;
}
