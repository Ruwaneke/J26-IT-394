package com.sentinel.tracker.controller;

import com.sentinel.tracker.analysis.LifecycleHashChain;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Hash-chain cases (TASKS P2-9) not covered by {@link LifecycleHistoryVerificationIntegrationTest}
 * (TASKS P1-5). Tampering uses direct SQL on H2 test rows, as someone with database access
 * would; no other data is touched.
 *
 * <p>The verification policy is pinned as it is: an event with no history is {@code BROKEN},
 * and leading rows without hashes (written before P2-9) are {@code UNCHAINED}.
 */
class LifecycleHashChainEdgeCaseIntegrationTest extends ApiContractTestSupport {

    private static final String VERIFY = "/api/lifecycle-history/security-event/{id}/verify";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private Long developerId;

    @BeforeEach
    void setUp() {
        developerId = createDeveloper("chain-edge-dev");
    }

    @Test
    void newEvent_withOnlyItsDetectedEntry_shouldBeValid() throws Exception {
        Long eventId = createEvent(developerId);

        verify(eventId)
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.entryCount").value(1));
        VulnerabilityLifecycleHistory first = history(eventId).get(0);
        assertThat(first.getPrevHash()).isEqualTo(LifecycleHashChain.GENESIS_HASH);
        assertThat(first.getEntryHash()).matches("[0-9a-f]{64}");
    }

    @Test
    void alteredEntryHashValue_shouldBreakAtThatEntry() throws Exception {
        Long eventId = eventWithThreeEntries();
        Long second = history(eventId).get(1).getId();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET entry_hash = ? WHERE id = ?",
                "f".repeat(64), second);

        expectBroken(eventId, 2, second, "entryHash does not match");
    }

    @Test
    void alteredPrevHashValue_shouldBreakAtThatEntry() throws Exception {
        Long eventId = eventWithThreeEntries();
        Long third = history(eventId).get(2).getId();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET prev_hash = ? WHERE id = ?",
                "a".repeat(64), third);

        expectBroken(eventId, 3, third, "prevHash does not match");
    }

    @Test
    void genesisValueReplacedOnFirstEntry_shouldBreakAtEntry1() throws Exception {
        Long eventId = eventWithThreeEntries();
        Long first = history(eventId).get(0).getId();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET prev_hash = ? WHERE id = ?",
                "1".repeat(64), first);

        expectBroken(eventId, 1, first, "prevHash does not match");
    }

    @Test
    void missingInitialDetectedEntry_shouldBreakAtEntry1() throws Exception {
        Long eventId = eventWithThreeEntries();
        List<VulnerabilityLifecycleHistory> entries = history(eventId);
        jdbcTemplate.update("DELETE FROM vulnerability_lifecycle_history WHERE id = ?", entries.get(0).getId());

        // The former second entry is now first, but chains to the deleted entry, not to genesis
        expectBroken(eventId, 1, entries.get(1).getId(), "prevHash does not match");
    }

    @Test
    void editedActorOnFirstEntry_shouldBreakAtEntry1() throws Exception {
        Long eventId = eventWithThreeEntries();
        Long first = history(eventId).get(0).getId();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET changed_by = ? WHERE id = ?",
                "someone-else", first);

        expectBroken(eventId, 1, first, "entryHash does not match");
    }

    @Test
    void entryMovedToAnotherEvent_shouldBreakBothChains() throws Exception {
        Long eventA = eventWithThreeEntries();
        Long eventB = eventWithThreeEntries();
        Long movedId = history(eventA).get(1).getId();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET security_event_id = ? WHERE id = ?",
                eventB, movedId);

        // A loses its second entry; B gains an entry whose hash names event A
        expectBroken(eventA, 2, history(eventA).get(1).getId(), "prevHash does not match");
        verify(eventB).andExpect(jsonPath("$.status").value("BROKEN"));
    }

    @Test
    void interleavedActionsOnTwoEvents_shouldKeepSeparateValidChains() throws Exception {
        Long eventA = createEvent(developerId);
        Long eventB = createEvent(developerId);
        sendAction(developerId, eventA, BehaviourAction.OPEN).andExpect(status().isCreated());
        sendAction(developerId, eventB, BehaviourAction.IGNORE).andExpect(status().isCreated());
        sendAction(developerId, eventA, BehaviourAction.FIX).andExpect(status().isCreated());
        sendAction(developerId, eventB, BehaviourAction.REOPEN).andExpect(status().isCreated());
        sendAction(developerId, eventB, BehaviourAction.FIX).andExpect(status().isCreated());

        verify(eventA).andExpect(jsonPath("$.status").value("VALID")).andExpect(jsonPath("$.entryCount").value(3));
        verify(eventB).andExpect(jsonPath("$.status").value("VALID")).andExpect(jsonPath("$.entryCount").value(4));
        // Each event's chain starts at genesis; chains never link across events
        assertThat(history(eventB).get(0).getPrevHash()).isEqualTo(LifecycleHashChain.GENESIS_HASH);
        assertThat(history(eventB).get(1).getPrevHash()).isEqualTo(history(eventB).get(0).getEntryHash());
    }

    @Test
    void clientTimestampsOutOfOrder_shouldStillVerifyBecauseTheChainFollowsIdOrder() throws Exception {
        Long eventId = createEvent(String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"2026-10-20T10:00:00\"}"));
        sendAction(developerId, eventId, BehaviourAction.IGNORE, "2026-10-20T12:00:00").andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.REOPEN, "2026-10-20T09:00:00").andExpect(status().isCreated());

        verify(eventId).andExpect(jsonPath("$.status").value("VALID")).andExpect(jsonPath("$.entryCount").value(3));
    }

    @Test
    void legacyEventWithNoHistoryAtAll_shouldStayBrokenAtEntry1() throws Exception {
        // As an event stored before P2-9 whose history is empty: the current policy reports
        // BROKEN, because every event gets a DETECTED entry when it is created
        Long eventId = insertLegacyEvent();

        verify(eventId)
                .andExpect(jsonPath("$.status").value("BROKEN"))
                .andExpect(jsonPath("$.entryCount").value(0))
                .andExpect(jsonPath("$.unchainedEntryCount").value(0))
                .andExpect(jsonPath("$.brokenAtEntry").value(1))
                .andExpect(jsonPath("$.brokenAtHistoryId").value(nullValue()))
                .andExpect(jsonPath("$.reason", containsString("DETECTED entry is missing")));
    }

    @Test
    void legacyEventWithUnhashedHistory_thenNewAction_shouldBeUnchainedAndStayVerifiable() throws Exception {
        Long eventId = insertLegacyEvent();
        insertLegacyHistory(eventId, null, "DETECTED", "2026-01-01T09:00:00");
        insertLegacyHistory(eventId, "DETECTED", "OPENED", "2026-01-01T09:05:00");
        jdbcTemplate.update("UPDATE security_events SET current_status = 'OPENED' WHERE id = ?", eventId);

        verify(eventId)
                .andExpect(jsonPath("$.status").value("UNCHAINED"))
                .andExpect(jsonPath("$.unchainedEntryCount").value(2));

        sendAction(developerId, eventId, BehaviourAction.FIX).andExpect(status().isCreated());

        verify(eventId)
                .andExpect(jsonPath("$.status").value("UNCHAINED"))
                .andExpect(jsonPath("$.entryCount").value(3))
                .andExpect(jsonPath("$.unchainedEntryCount").value(2));
        // The first chained entry after legacy rows starts from genesis (LifecycleHashChain.nextPrevHash)
        assertThat(history(eventId).get(2).getPrevHash()).isEqualTo(LifecycleHashChain.GENESIS_HASH);
    }

    @Test
    void legacyEntries_areNeverBackfilledByVerification() throws Exception {
        Long eventId = insertLegacyEvent();
        insertLegacyHistory(eventId, null, "DETECTED", "2026-01-01T09:00:00");

        verify(eventId).andExpect(jsonPath("$.status").value("UNCHAINED"));
        verify(eventId).andExpect(jsonPath("$.status").value("UNCHAINED"));

        VulnerabilityLifecycleHistory legacy = history(eventId).get(0);
        assertThat(legacy.getPrevHash()).isNull();
        assertThat(legacy.getEntryHash()).isNull();
    }

    @Test
    void nonexistentEvent_shouldReturn404() throws Exception {
        mockMvc.perform(get(VERIFY, Long.MAX_VALUE))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message", containsString("Security event not found")));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** DETECTED, OPENED, IGNORED. */
    private Long eventWithThreeEntries() throws Exception {
        Long eventId = createEvent(developerId);
        sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());
        sendAction(developerId, eventId, BehaviourAction.IGNORE).andExpect(status().isCreated());
        assertThat(history(eventId)).hasSize(3);
        verify(eventId).andExpect(jsonPath("$.status").value("VALID"));
        return eventId;
    }

    /** An event row as written before P2-9: no history entry and no hash columns used. */
    private Long insertLegacyEvent() {
        Timestamp now = Timestamp.valueOf(LocalDateTime.of(2026, 1, 1, 9, 0));
        jdbcTemplate.update("INSERT INTO security_events (developer_id, vulnerability_type, severity, file_name, "
                        + "line_number, message, detected_at, current_status, created_at, updated_at) "
                        + "VALUES (?, 'XSS', 'MEDIUM', 'legacy.js', 3, 'legacy event', ?, 'DETECTED', ?, ?)",
                developerId, now, now, now);
        return jdbcTemplate.queryForObject("SELECT MAX(id) FROM security_events", Long.class);
    }

    private void insertLegacyHistory(Long eventId, String previous, String next, String changedAt) {
        Timestamp at = Timestamp.valueOf(LocalDateTime.parse(changedAt));
        jdbcTemplate.update("INSERT INTO vulnerability_lifecycle_history (security_event_id, previous_status, "
                        + "new_status, changed_at, changed_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                eventId, previous, next, at, previous == null ? "SYSTEM" : "chain-edge-dev", at);
    }

    private List<VulnerabilityLifecycleHistory> history(Long eventId) {
        return lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId);
    }

    private ResultActions verify(Long eventId) throws Exception {
        return mockMvc.perform(get(VERIFY, eventId)).andExpect(status().isOk());
    }

    private void expectBroken(Long eventId, int entry, Long historyId, String reasonFragment) throws Exception {
        verify(eventId)
                .andExpect(jsonPath("$.status").value("BROKEN"))
                .andExpect(jsonPath("$.brokenAtEntry").value(entry))
                .andExpect(jsonPath("$.brokenAtHistoryId").value(historyId))
                .andExpect(jsonPath("$.reason", containsString(reasonFragment)));
    }
}
