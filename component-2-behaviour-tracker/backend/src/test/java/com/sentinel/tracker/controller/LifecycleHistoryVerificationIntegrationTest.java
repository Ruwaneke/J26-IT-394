package com.sentinel.tracker.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.tracker.analysis.LifecycleHashChain;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tamper tests for the lifecycle hash chain (TASKS P2-9) through the real write path, the
 * verify endpoint and the H2 database. Tampering is done with direct SQL, as someone with
 * database access would.
 *
 * <p>Each test starts from one event with five entries, in id order:
 * 1 DETECTED, 2 OPENED, 3 IGNORED, 4 REOPENED, 5 FIXED.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LifecycleHistoryVerificationIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(LifecycleHistoryVerificationIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private DeveloperRepository developerRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private BehaviourLogRepository behaviourLogRepository;

    @Autowired
    private VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    private Long developerId;
    private Long eventId;
    private List<Long> historyIds;

    @BeforeEach
    void setUp() throws Exception {
        developerId = developerRepository.save(
                Developer.builder().developerIdentifier("chain-dev").build()).getId();
        eventId = createEvent();

        sendAction(BehaviourAction.OPEN, "2026-10-20T10:01:00");
        // Nanosecond precision must not break the chain once stored at microsecond precision
        sendAction(BehaviourAction.IGNORE, "2026-10-20T10:02:00.123456789");
        sendAction(BehaviourAction.REOPEN, "2026-10-20T10:03:00");
        sendAction(BehaviourAction.FIX, "2026-10-20T10:04:00");

        historyIds = lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId).stream()
                .map(VulnerabilityLifecycleHistory::getId)
                .toList();
        assertThat(historyIds).hasSize(5);
    }

    @AfterEach
    void tearDown() {
        lifecycleHistoryRepository.deleteAll();
        behaviourLogRepository.deleteAll();
        securityEventRepository.deleteAll();
        developerRepository.deleteAll();
    }

    // ── No tampering ──────────────────────────────────────────────────────────

    @Test
    void verify_untouchedHistory_shouldReturnValid() throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.securityEventId").value(eventId))
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.entryCount").value(5))
                .andExpect(jsonPath("$.unchainedEntryCount").value(0))
                .andExpect(jsonPath("$.brokenAtEntry").doesNotExist())
                .andExpect(jsonPath("$.verifiedAt").exists());
    }

    @Test
    void verify_aliasPath_shouldReturnValid() throws Exception {
        mockMvc.perform(get("/api/lifecycle/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALID"));
    }

    @Test
    void history_shouldExposeEntryHash() throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].entryHash").isString())
                .andExpect(jsonPath("$[4].entryHash").isString());
    }

    @Test
    void verify_unknownEvent_shouldReturn404() throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", 999_999L))
                .andExpect(status().isNotFound());
    }

    // ── Tampering ─────────────────────────────────────────────────────────────

    @Test
    void verify_editedStatusInMiddleEntry_shouldBreakAtThatEntry() throws Exception {
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET new_status = 'FIXED' WHERE id = ?",
                historyIds.get(2));

        expectBroken(3, historyIds.get(2), "edited");
    }

    @Test
    void verify_editedTimestamp_shouldBreakAtThatEntry() throws Exception {
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET changed_at = ? WHERE id = ?",
                Timestamp.valueOf(LocalDateTime.of(2026, 10, 20, 9, 0)), historyIds.get(2));

        expectBroken(3, historyIds.get(2), "edited");
    }

    @Test
    void verify_deletedMiddleEntry_shouldBreakAtTheNextEntry() throws Exception {
        jdbcTemplate.update("DELETE FROM vulnerability_lifecycle_history WHERE id = ?", historyIds.get(2));

        // The former 4th entry is now 3rd and no longer follows the 2nd
        expectBroken(3, historyIds.get(3), "deleted, inserted or reordered");
    }

    @Test
    void verify_reorderedEntries_shouldBreakAtTheFirstMovedEntry() throws Exception {
        swapContents(historyIds.get(1), historyIds.get(2));

        expectBroken(2, historyIds.get(1), "deleted, inserted or reordered");
    }

    @Test
    void verify_editedEntryWithRecomputedHash_shouldBreakAtTheNextEntry() throws Exception {
        // An attacker who knows the algorithm re-hashes the edited entry but not the rest of the chain
        VulnerabilityLifecycleHistory forged = lifecycleHistoryRepository.findById(historyIds.get(2)).orElseThrow();
        forged.setNewStatus(SecurityEventStatus.FIXED);
        String forgedHash = LifecycleHashChain.computeEntryHash(forged.getPrevHash(), forged);
        jdbcTemplate.update(
                "UPDATE vulnerability_lifecycle_history SET new_status = 'FIXED', entry_hash = ? WHERE id = ?",
                forgedHash, historyIds.get(2));

        expectBroken(4, historyIds.get(3), "deleted, inserted or reordered");
    }

    @Test
    void verify_hashRemovedFromMiddleEntry_shouldBreakAtThatEntry() throws Exception {
        jdbcTemplate.update(
                "UPDATE vulnerability_lifecycle_history SET prev_hash = NULL, entry_hash = NULL WHERE id = ?",
                historyIds.get(2));

        expectBroken(3, historyIds.get(2), "no hash");
    }

    @Test
    void verify_allEntriesDeleted_shouldBreakAtFirstEntry() throws Exception {
        jdbcTemplate.update("DELETE FROM vulnerability_lifecycle_history WHERE security_event_id = ?", eventId);

        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BROKEN"))
                .andExpect(jsonPath("$.entryCount").value(0))
                .andExpect(jsonPath("$.brokenAtEntry").value(1));
    }

    @Test
    void verify_newestEntryDeleted_isNotDetectedWithoutAnOutsideAnchor() throws Exception {
        // Documented limit: the chain alone cannot tell a truncated history from a shorter one
        jdbcTemplate.update("DELETE FROM vulnerability_lifecycle_history WHERE id = ?", historyIds.get(4));

        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.entryCount").value(4));
    }

    // ── Entries written before the hash chain ─────────────────────────────────

    @Test
    void verify_legacyEntriesOnly_shouldReturnUnchained() throws Exception {
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET prev_hash = NULL, entry_hash = NULL "
                + "WHERE security_event_id = ?", eventId);

        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UNCHAINED"))
                .andExpect(jsonPath("$.entryCount").value(5))
                .andExpect(jsonPath("$.unchainedEntryCount").value(5))
                .andExpect(jsonPath("$.brokenAtEntry").doesNotExist());
    }

    @Test
    void verify_newEntriesAfterLegacyEntry_shouldChainFromGenesisAndReturnUnchained() throws Exception {
        Long legacyEventId = createEvent();
        jdbcTemplate.update("UPDATE vulnerability_lifecycle_history SET prev_hash = NULL, entry_hash = NULL "
                + "WHERE security_event_id = ?", legacyEventId);

        sendAction(legacyEventId, BehaviourAction.OPEN, "2026-10-20T11:00:00");

        assertThat(lifecycleHistoryRepository.findFirstBySecurityEventIdOrderByIdDesc(legacyEventId)
                .orElseThrow().getPrevHash()).isEqualTo(LifecycleHashChain.GENESIS_HASH);
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", legacyEventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UNCHAINED"))
                .andExpect(jsonPath("$.entryCount").value(2))
                .andExpect(jsonPath("$.unchainedEntryCount").value(1));
    }

    // ── Cost (evidence for the evaluation, TASKS P4-3) ────────────────────────

    @Test
    void chainCost_longChainStaysValid_andExtraWorkPerEntryIsRecorded() throws Exception {
        // 200 more transitions: FIXED -> REOPENED -> IGNORED -> REOPENED -> ...
        sendAction(BehaviourAction.REOPEN, "2026-10-20T12:00:00");
        for (int i = 0; i < 199; i++) {
            BehaviourAction action = i % 2 == 0 ? BehaviourAction.IGNORE : BehaviourAction.REOPEN;
            sendAction(action, LocalDateTime.of(2026, 10, 20, 12, 0).plusSeconds(i + 1L).toString());
        }

        // The work the chain adds to each history write: read the latest entry, then hash
        SecurityEvent event = securityEventRepository.findById(eventId).orElseThrow();
        int runs = 1_000;
        long start = System.nanoTime();
        for (int i = 0; i < runs; i++) {
            VulnerabilityLifecycleHistory entry = VulnerabilityLifecycleHistory.builder()
                    .securityEvent(event)
                    .previousStatus(SecurityEventStatus.IGNORED)
                    .newStatus(SecurityEventStatus.REOPENED)
                    .changedAt(LocalDateTime.now())
                    .changedBy("chain-dev")
                    .build();
            LifecycleHashChain.seal(entry, LifecycleHashChain.nextPrevHash(
                    lifecycleHistoryRepository.findFirstBySecurityEventIdOrderByIdDesc(eventId)));
        }
        double extraMsPerEntry = (System.nanoTime() - start) / 1_000_000.0 / runs;

        start = System.nanoTime();
        String body = mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.entryCount").value(205))
                .andReturn().getResponse().getContentAsString();
        double verifyMs = (System.nanoTime() - start) / 1_000_000.0;

        log.info("Hash chain cost (H2, in-process): {} ms extra per history write; verify of {} entries in {} ms",
                String.format("%.4f", extraMsPerEntry), objectMapper.readTree(body).get("entryCount").asInt(),
                String.format("%.1f", verifyMs));
        assertThat(extraMsPerEntry).isPositive();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Long createEvent() throws Exception {
        String body = mockMvc.perform(post("/api/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"developerId\":" + developerId + ",\"vulnerabilityType\":\"SQL_INJECTION\","
                                + "\"severity\":\"HIGH\",\"fileName\":\"UserDao.java\",\"lineNumber\":42,"
                                + "\"message\":\"Unparameterised query\",\"detectedAt\":\"2026-10-20T10:00:00\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        JsonNode created = objectMapper.readTree(body);
        return created.get("id").asLong();
    }

    private void sendAction(BehaviourAction action, String actionTimestamp) throws Exception {
        sendAction(eventId, action, actionTimestamp);
    }

    private void sendAction(Long securityEventId, BehaviourAction action, String actionTimestamp) throws Exception {
        mockMvc.perform(post("/api/developer-interactions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"developerId\":" + developerId + ",\"securityEventId\":" + securityEventId
                                + ",\"action\":\"" + action + "\",\"actionTimestamp\":\"" + actionTimestamp
                                + "\",\"sessionId\":\"s-1\",\"source\":\"VSCODE\"}"))
                .andExpect(status().isCreated());
    }

    private void expectBroken(int entry, Long historyId, String reasonFragment) throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("BROKEN"))
                .andExpect(jsonPath("$.brokenAtEntry").value(entry))
                .andExpect(jsonPath("$.brokenAtHistoryId").value(historyId))
                .andExpect(jsonPath("$.reason", org.hamcrest.Matchers.containsString(reasonFragment)));
    }

    /** Swaps every stored column except the id, so the two entries change places in id order. */
    private void swapContents(Long firstId, Long secondId) {
        String select = "SELECT previous_status, new_status, changed_at, changed_by, prev_hash, entry_hash "
                + "FROM vulnerability_lifecycle_history WHERE id = ?";
        Map<String, Object> first = jdbcTemplate.queryForMap(select, firstId);
        Map<String, Object> second = jdbcTemplate.queryForMap(select, secondId);
        String update = "UPDATE vulnerability_lifecycle_history SET previous_status = ?, new_status = ?, "
                + "changed_at = ?, changed_by = ?, prev_hash = ?, entry_hash = ? WHERE id = ?";
        jdbcTemplate.update(update, second.get("PREVIOUS_STATUS"), second.get("NEW_STATUS"), second.get("CHANGED_AT"),
                second.get("CHANGED_BY"), second.get("PREV_HASH"), second.get("ENTRY_HASH"), firstId);
        jdbcTemplate.update(update, first.get("PREVIOUS_STATUS"), first.get("NEW_STATUS"), first.get("CHANGED_AT"),
                first.get("CHANGED_BY"), first.get("PREV_HASH"), first.get("ENTRY_HASH"), secondId);
    }
}
