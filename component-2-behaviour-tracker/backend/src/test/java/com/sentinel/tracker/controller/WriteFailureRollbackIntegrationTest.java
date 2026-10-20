package com.sentinel.tracker.controller;

import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Database consistency when a write fails half-way (TASKS P1-5).
 *
 * <p>A temporary {@code CHECK} constraint on the H2 test table makes the lifecycle-history
 * insert fail with a real database error, after the event or behaviour log was already
 * inserted in the same transaction. The whole transaction must roll back: no event without
 * its {@code DETECTED} entry, no log or status change without its history entry. The
 * constraint is dropped after each test.
 */
class WriteFailureRollbackIntegrationTest extends ApiContractTestSupport {

    private static final String CONSTRAINT = "test_reject_history_write";
    private static final String GENERIC_500 = "An unexpected error occurred. Please check the server logs.";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @AfterEach
    void dropConstraint() {
        jdbcTemplate.execute("ALTER TABLE vulnerability_lifecycle_history DROP CONSTRAINT IF EXISTS " + CONSTRAINT);
    }

    @Test
    void createEvent_historyInsertFails_shouldRollBackTheEvent() throws Exception {
        Long developerId = createDeveloper("rollback-event-dev");
        acceptHistoryRowsOnlyWhere("changed_at <> TIMESTAMP '1999-12-31 23:59:59'");

        postJson("/api/security-events", String.format(C1_EVENT_BODY, developerId)
                .replace("}", ",\"detectedAt\":\"1999-12-31T23:59:59\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(apiError(500, "Internal Server Error", "/api/security-events"))
                // Database details stay in the server log
                .andExpect(jsonPath("$.message").value(GENERIC_500));

        assertThat(securityEventRepository.count()).isZero();
        assertThat(lifecycleHistoryRepository.count()).isZero();
    }

    @Test
    void createInteraction_historyInsertFails_shouldRollBackLogAndStatus() throws Exception {
        Long developerId = createDeveloper("rollback-action-dev");
        Long eventId = createEvent(developerId);
        sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());
        List<Long> historyBefore = historyIds(eventId);

        acceptHistoryRowsOnlyWhere("new_status <> 'FIXED'");
        sendAction(developerId, eventId, BehaviourAction.FIX)
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value(GENERIC_500));

        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.OPENED);
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(1);
        assertThat(historyIds(eventId)).isEqualTo(historyBefore);
        expectChainValid(eventId);

        // Once the database accepts the write again, the same action succeeds and chains on
        dropConstraint();
        sendAction(developerId, eventId, BehaviourAction.FIX).andExpect(status().isCreated());
        assertThat(currentStatus(eventId)).isEqualTo(SecurityEventStatus.FIXED);
        assertThat(historyIds(eventId)).hasSize(3);
        expectChainValid(eventId);
    }

    @Test
    void sameStatusAction_isUnaffectedByAHistoryWriteFailure() throws Exception {
        Long developerId = createDeveloper("rollback-same-dev");
        Long eventId = createEvent(developerId);
        sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());

        // A same-status action writes no history row (P1-1), so a failing history table does not matter
        acceptHistoryRowsOnlyWhere("1 = 0");
        sendAction(developerId, eventId, BehaviourAction.OPEN).andExpect(status().isCreated());

        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(2);
        assertThat(historyIds(eventId)).hasSize(2);
    }

    @Test
    void noOrphans_afterMixedSuccessAndFailure() throws Exception {
        Long developerId = createDeveloper("rollback-orphan-dev");
        Long eventId = createEvent(developerId);
        acceptHistoryRowsOnlyWhere("new_status <> 'IGNORED'");
        sendAction(developerId, eventId, BehaviourAction.IGNORE).andExpect(status().isInternalServerError());
        dropConstraint();
        sendAction(developerId, eventId, BehaviourAction.FIX).andExpect(status().isCreated());

        // Every log points at an existing event and developer; every status change has its history row
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM behaviour_logs l "
                + "LEFT JOIN security_events e ON l.security_event_id = e.id "
                + "LEFT JOIN developers d ON l.developer_id = d.id WHERE e.id IS NULL OR d.id IS NULL", Long.class))
                .isZero();
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM vulnerability_lifecycle_history h "
                + "LEFT JOIN security_events e ON h.security_event_id = e.id WHERE e.id IS NULL", Long.class))
                .isZero();
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId))
                .extracting(l -> l.getActionType()).containsExactly(BehaviourAction.FIX);
        assertThat(lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId))
                .extracting(VulnerabilityLifecycleHistory::getNewStatus)
                .containsExactly(SecurityEventStatus.DETECTED, SecurityEventStatus.FIXED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Makes the database reject every new history row for which {@code allowed} is false. */
    private void acceptHistoryRowsOnlyWhere(String allowed) {
        jdbcTemplate.execute("ALTER TABLE vulnerability_lifecycle_history ADD CONSTRAINT " + CONSTRAINT
                + " CHECK (" + allowed + ") NOCHECK");
    }

    private List<Long> historyIds(Long eventId) {
        return lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId).stream()
                .map(VulnerabilityLifecycleHistory::getId).toList();
    }

    private void expectChainValid(Long eventId) throws Exception {
        mockMvc.perform(get("/api/lifecycle-history/security-event/{id}/verify", eventId))
                .andExpect(jsonPath("$.status").value("VALID"));
    }
}
