package com.sentinel.tracker.controller;

import com.sentinel.tracker.enums.BehaviourAction;
import org.junit.jupiter.api.Test;

import static com.sentinel.tracker.enums.BehaviourAction.FIX;
import static com.sentinel.tracker.enums.BehaviourAction.IGNORE;
import static com.sentinel.tracker.enums.BehaviourAction.OPEN;
import static com.sentinel.tracker.enums.BehaviourAction.REOPEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/developer-behaviour/{developerId}/response-sequences} on the real stack
 * (TASKS P2-10). Data is written through the real C1 endpoints, so every event also has the
 * SYSTEM-written DETECTED history entry and a history entry per status change.
 */
class ResponseSequenceApiIntegrationTest extends ApiContractTestSupport {

    private static final String PATH = "/api/developer-behaviour/%d/response-sequences";

    @Test
    void c1Actions_shouldGiveTheHandCalculatedSequencesWithoutSystemEntries() throws Exception {
        Long developer = createDeveloper("sequence-dev");
        Long e1 = createEvent(developer);
        Long e2 = createEvent(developer);
        Long e3 = createEvent(developer);
        act(developer, e1, OPEN, 0);
        act(developer, e1, FIX, 1);
        act(developer, e2, OPEN, 2);
        act(developer, e2, FIX, 3);
        act(developer, e3, OPEN, 4);
        act(developer, e3, OPEN, 5);   // secure example viewed: same-status, logged
        act(developer, e3, IGNORE, 6);
        act(developer, e3, REOPEN, 7);
        act(developer, e3, FIX, 8);
        // Rejected by the lifecycle (409): nothing stored, so never part of a sequence
        sendAction(developer, e1, OPEN, timestamp(9)).andExpect(status().isConflict());

        // 3 sequences: OPEN FIX · OPEN FIX · OPEN IGNORE REOPEN FIX (repeat OPEN merged)
        mockMvc.perform(get(String.format(PATH, developer)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.developerId").value(developer))
                .andExpect(jsonPath("$.analysisStatus").value("ANALYSED"))
                .andExpect(jsonPath("$.insufficientDataReason").doesNotExist())
                .andExpect(jsonPath("$.totalActionRecords").value(9))
                .andExpect(jsonPath("$.excludedActionRecords").value(0))
                .andExpect(jsonPath("$.collapsedRepeatActions").value(1))
                .andExpect(jsonPath("$.totalEligibleEvents").value(3))
                .andExpect(jsonPath("$.totalEligibleSequences").value(3))
                .andExpect(jsonPath("$.thresholds.minSequences").value(3))
                .andExpect(jsonPath("$.dominantPattern.status").value("FOUND"))
                .andExpect(jsonPath("$.dominantPattern.actions[0]").value("OPEN"))
                .andExpect(jsonPath("$.dominantPattern.actions[1]").value("FIX"))
                .andExpect(jsonPath("$.dominantPattern.actions.length()").value(2))
                .andExpect(jsonPath("$.dominantPattern.occurrenceCount").value(2))
                .andExpect(jsonPath("$.dominantPattern.supportPercent").value(66.7))
                .andExpect(jsonPath("$.dominantPattern.lastOccurredAt").value("2030-01-01T10:03:00"))
                // OPEN FIX is in e1 and e2 only (e3 ends REOPEN FIX)
                .andExpect(jsonPath("$.frequentPatterns.length()").value(1))
                .andExpect(jsonPath("$.frequentPatterns[0].occurrenceCount").value(2))
                .andExpect(jsonPath("$.frequentPatterns[0].sequenceCount").value(2))
                .andExpect(jsonPath("$.frequentPatterns[0].supportPercent").value(66.7))
                .andExpect(jsonPath("$.frequentPatterns[0].eligibleSequenceCount").value(3))
                // OPEN leaves 3 times: FIX 2 (66.7%), IGNORE 1 (33.3%)
                .andExpect(jsonPath("$.transitionAnalysis.length()").value(4))
                .andExpect(jsonPath("$.transitionAnalysis[0].fromAction").value("OPEN"))
                .andExpect(jsonPath("$.transitionAnalysis[0].toAction").value("FIX"))
                .andExpect(jsonPath("$.transitionAnalysis[0].transitionCount").value(2))
                .andExpect(jsonPath("$.transitionAnalysis[0].outgoingSampleSize").value(3))
                .andExpect(jsonPath("$.transitionAnalysis[0].probabilityPercent").value(66.7))
                .andExpect(jsonPath("$.transitionAnalysis[0].sufficientSample").value(false))
                .andExpect(jsonPath("$.transitionAnalysis[1].toAction").value("IGNORE"))
                .andExpect(jsonPath("$.transitionAnalysis[1].probabilityPercent").value(33.3))
                // The DETECTED history entries (changed by SYSTEM) are never actions
                .andExpect(content().string(not(containsString("DETECTED"))));

        assertThat(lifecycleHistoryRepository.findAll())
                .filteredOn(h -> "SYSTEM".equals(h.getChangedBy())).hasSize(3);
    }

    @Test
    void otherDevelopersActions_shouldStaySeparate() throws Exception {
        Long alice = createDeveloper("sequence-alice");
        Long bob = createDeveloper("sequence-bob");
        for (int i = 0; i < 3; i++) {
            Long event = createEvent(alice);
            act(alice, event, OPEN, 2 * i);
            act(alice, event, FIX, 2 * i + 1);
        }
        Long bobsEvent = createEvent(bob);
        act(bob, bobsEvent, OPEN, 0);
        act(bob, bobsEvent, IGNORE, 1);
        // Bob acting on Alice's event is refused (403) and stored nowhere
        Long alicesEvent = createEvent(alice);
        sendAction(bob, alicesEvent, IGNORE, timestamp(2)).andExpect(status().isForbidden());

        mockMvc.perform(get(String.format(PATH, alice)))
                .andExpect(jsonPath("$.totalActionRecords").value(6))
                .andExpect(jsonPath("$.transitionAnalysis.length()").value(1))
                .andExpect(jsonPath("$.dominantPattern.occurrenceCount").value(3))
                .andExpect(jsonPath("$.dominantPattern.supportPercent").value(100.0));
        mockMvc.perform(get(String.format(PATH, bob)))
                .andExpect(jsonPath("$.totalActionRecords").value(2))
                .andExpect(jsonPath("$.analysisStatus").value("INSUFFICIENT_DATA"))
                .andExpect(jsonPath("$.insufficientDataReason")
                        .value("Only 1 complete response sequence; at least 3 are needed"));
    }

    @Test
    void developerWithEventsButNoActions_shouldBeInsufficientData() throws Exception {
        Long developer = createDeveloper("sequence-no-actions");
        createEvent(developer);

        mockMvc.perform(get(String.format(PATH, developer)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.analysisStatus").value("INSUFFICIENT_DATA"))
                .andExpect(jsonPath("$.insufficientDataReason").value("No developer actions are recorded for this developer"))
                .andExpect(jsonPath("$.totalEligibleEvents").value(0))
                .andExpect(jsonPath("$.dominantPattern.status").value("INSUFFICIENT_DATA"))
                .andExpect(jsonPath("$.frequentPatterns.length()").value(0))
                .andExpect(jsonPath("$.transitionAnalysis.length()").value(0));
    }

    @Test
    void unknownDeveloper_shouldReturn404() throws Exception {
        mockMvc.perform(get(String.format(PATH, 999_999L)))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", String.format(PATH, 999_999L)));
    }

    @Test
    void unmappedRoute_shouldReturn404NamingTheEndpointNotAGeneric500() throws Exception {
        // Regression (2026-10-21): a backend started before this endpoint existed answered
        // GET .../response-sequences with the catch-all 500 "unexpected error", which hid that
        // the route was simply not registered. An unknown route must say so.
        Long developer = createDeveloper("sequence-unmapped");
        String path = "/api/developer-behaviour/" + developer + "/no-such-analysis";

        mockMvc.perform(get(path))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", path))
                .andExpect(jsonPath("$.message").value("No endpoint GET " + path + " on this server. "
                        + "If it was added recently, restart the backend so it is registered."));
    }

    @Test
    void analysis_shouldBeReadOnly() throws Exception {
        Long developer = createDeveloper("sequence-read-only");
        Long event = createEvent(developer);
        act(developer, event, OPEN, 0);
        long logs = behaviourLogRepository.count();
        long history = lifecycleHistoryRepository.count();
        long events = securityEventRepository.count();

        mockMvc.perform(get(String.format(PATH, developer))).andExpect(status().isOk());

        assertThat(behaviourLogRepository.count()).isEqualTo(logs);
        assertThat(lifecycleHistoryRepository.count()).isEqualTo(history);
        assertThat(securityEventRepository.count()).isEqualTo(events);
    }

    @Test
    void behaviourSummary_shouldBeUnaffected() throws Exception {
        Long developer = createDeveloper("sequence-summary");
        Long event = createEvent(developer);
        act(developer, event, OPEN, 0);
        act(developer, event, FIX, 1);

        mockMvc.perform(get("/api/developer-behaviour/" + developer))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fixedCount").value(1))
                .andExpect(jsonPath("$.frequentPatterns").doesNotExist());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void act(Long developerId, Long eventId, BehaviourAction action, int minute) throws Exception {
        sendAction(developerId, eventId, action, timestamp(minute)).andExpect(status().isCreated());
    }

    private static String timestamp(int minute) {
        return String.format("2030-01-01T10:%02d:00", minute);
    }
}
