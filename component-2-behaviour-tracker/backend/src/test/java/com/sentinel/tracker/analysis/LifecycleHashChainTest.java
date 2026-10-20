package com.sentinel.tracker.analysis;

import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.SecurityEventStatus;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link LifecycleHashChain}.
 */
class LifecycleHashChainTest {

    private static final String PREV = "a".repeat(64);

    @Test
    void computeEntryHash_sameInput_shouldGiveSameHash() {
        assertThat(LifecycleHashChain.computeEntryHash(PREV, entry()))
                .isEqualTo(LifecycleHashChain.computeEntryHash(PREV, entry()))
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void computeEntryHash_anyFieldChanged_shouldChangeHash() {
        String original = LifecycleHashChain.computeEntryHash(PREV, entry());

        assertThat(LifecycleHashChain.computeEntryHash("b".repeat(64), entry())).isNotEqualTo(original);
        assertChanged(original, e -> e.setSecurityEvent(SecurityEvent.builder().id(11L).build()));
        assertChanged(original, e -> e.setPreviousStatus(SecurityEventStatus.DETECTED));
        assertChanged(original, e -> e.setNewStatus(SecurityEventStatus.FIXED));
        assertChanged(original, e -> e.setChangedAt(e.getChangedAt().plusNanos(1_000)));
        assertChanged(original, e -> e.setChangedBy("mallory"));
    }

    @Test
    void computeEntryHash_subMicrosecondDifference_shouldNotChangeHash() {
        VulnerabilityLifecycleHistory withNanos = entry();
        withNanos.setChangedAt(withNanos.getChangedAt().plusNanos(999));

        assertThat(LifecycleHashChain.computeEntryHash(PREV, withNanos))
                .isEqualTo(LifecycleHashChain.computeEntryHash(PREV, entry()));
    }

    @Test
    void normalise_shouldTruncateToMicroseconds() {
        LocalDateTime time = LocalDateTime.of(2026, 10, 20, 10, 0, 0, 123_456_789);

        assertThat(LifecycleHashChain.normalise(time))
                .isEqualTo(LocalDateTime.of(2026, 10, 20, 10, 0, 0, 123_456_000));
        assertThat(LifecycleHashChain.normalise(null)).isNull();
    }

    @Test
    void seal_shouldNormaliseTimeAndSetBothHashes() {
        VulnerabilityLifecycleHistory entry = entry();
        entry.setChangedAt(entry.getChangedAt().plusNanos(789));

        LifecycleHashChain.seal(entry, PREV);

        assertThat(entry.getChangedAt().getNano() % 1_000).isZero();
        assertThat(entry.getPrevHash()).isEqualTo(PREV);
        assertThat(entry.getEntryHash()).isEqualTo(LifecycleHashChain.computeEntryHash(PREV, entry));
    }

    @Test
    void nextPrevHash_shouldUseLatestEntryHashOrGenesis() {
        VulnerabilityLifecycleHistory chained = entry();
        chained.setEntryHash(PREV);
        VulnerabilityLifecycleHistory legacy = entry();

        assertThat(LifecycleHashChain.nextPrevHash(Optional.of(chained))).isEqualTo(PREV);
        assertThat(LifecycleHashChain.nextPrevHash(Optional.of(legacy))).isEqualTo(LifecycleHashChain.GENESIS_HASH);
        assertThat(LifecycleHashChain.nextPrevHash(Optional.empty())).isEqualTo(LifecycleHashChain.GENESIS_HASH);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void assertChanged(String original, Consumer<VulnerabilityLifecycleHistory> change) {
        VulnerabilityLifecycleHistory entry = entry();
        change.accept(entry);
        assertThat(LifecycleHashChain.computeEntryHash(PREV, entry)).isNotEqualTo(original);
    }

    private VulnerabilityLifecycleHistory entry() {
        return VulnerabilityLifecycleHistory.builder()
                .securityEvent(SecurityEvent.builder().id(10L).build())
                .previousStatus(SecurityEventStatus.OPENED)
                .newStatus(SecurityEventStatus.IGNORED)
                .changedAt(LocalDateTime.of(2026, 10, 20, 10, 5, 0, 123_456_000))
                .changedBy("octocat")
                .build();
    }
}
