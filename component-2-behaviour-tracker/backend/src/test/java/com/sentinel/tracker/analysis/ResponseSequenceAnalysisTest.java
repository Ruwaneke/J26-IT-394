package com.sentinel.tracker.analysis;

import com.sentinel.tracker.analysis.ResponseSequenceAnalysis.ActionRecord;
import com.sentinel.tracker.analysis.ResponseSequenceAnalysis.Thresholds;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse.ActionTransition;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse.SequencePattern;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.DominantPatternStatus;
import com.sentinel.tracker.enums.SequenceAnalysisStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static com.sentinel.tracker.enums.BehaviourAction.DISMISS;
import static com.sentinel.tracker.enums.BehaviourAction.FIX;
import static com.sentinel.tracker.enums.BehaviourAction.IGNORE;
import static com.sentinel.tracker.enums.BehaviourAction.OPEN;
import static com.sentinel.tracker.enums.BehaviourAction.REOPEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ResponseSequenceAnalysis} (TASKS P2-10) on hand-built, deterministic
 * fixtures. Expected values are calculated by hand in the comments.
 */
class ResponseSequenceAnalysisTest {

    /** The defaults of application.properties: 3 sequences, 2 per pattern, 10% support, 5 per transition. */
    private static final Thresholds DEFAULTS = new Thresholds(3, 2, 10.0, 5);
    /** Reports everything, to inspect sequence construction alone. */
    private static final Thresholds REPORT_ALL = new Thresholds(1, 1, 0.0, 1);
    private static final LocalDateTime T0 = LocalDateTime.of(2026, 10, 21, 9, 0, 0);

    private List<ActionRecord> records;
    private Set<Long> ownEvents;
    private long nextLogId;

    @BeforeEach
    void setUp() {
        records = new ArrayList<>();
        ownEvents = new TreeSet<>();
        nextLogId = 1;
    }

    // ── Sequence construction ─────────────────────────────────────────────────

    @Test
    void actions_shouldBeOrderedByTimestampNotByInsertion() {
        // Inserted FIX, REOPEN, IGNORE, OPEN; the timestamps say OPEN, IGNORE, REOPEN, FIX
        action(1, FIX, 40);
        action(1, REOPEN, 30);
        action(1, IGNORE, 20);
        action(1, OPEN, 10);

        assertThat(analyse(REPORT_ALL).getDominantPattern().getActions()).containsExactly(OPEN, IGNORE, REOPEN, FIX);
    }

    @Test
    void equalTimestamps_shouldKeepInsertionOrder() {
        action(1, OPEN, 10);
        action(1, FIX, 10);

        assertThat(analyse(REPORT_ALL).getDominantPattern().getActions()).containsExactly(OPEN, FIX);
    }

    @Test
    void actionsOnDifferentEvents_shouldNeverFormOneSequence() {
        // OPEN on event 1 then FIX on event 2 is not OPEN -> FIX
        action(1, OPEN, 10);
        action(2, FIX, 11);

        ResponseSequenceAnalysisResponse result = analyse(REPORT_ALL);

        assertThat(result.getTotalEligibleSequences()).isEqualTo(2);
        assertThat(result.getSingleActionSequences()).isEqualTo(2);
        assertThat(result.getFrequentPatterns()).isEmpty();
        assertThat(result.getTransitionAnalysis()).isEmpty();
    }

    @Test
    void actionsOnOtherDevelopersEventsOrNoEvent_shouldBeExcluded() {
        action(1, OPEN, 10);
        action(1, FIX, 11);
        records.add(new ActionRecord(nextLogId++, 99L, OPEN, T0));   // another developer's event
        records.add(new ActionRecord(nextLogId++, null, IGNORE, T0)); // event deleted

        ResponseSequenceAnalysisResponse result = analyse(REPORT_ALL);

        assertThat(result.getTotalActionRecords()).isEqualTo(4);
        assertThat(result.getExcludedActionRecords()).isEqualTo(2);
        assertThat(result.getTotalEligibleEvents()).isEqualTo(1);
        assertThat(result.getDominantPattern().getActions()).containsExactly(OPEN, FIX);
    }

    @Test
    void theSameRecordTwice_shouldCountOnce() {
        ActionRecord open = new ActionRecord(1L, 1L, OPEN, T0);
        ownEvents.add(1L);
        records.add(open);
        records.add(open);
        records.add(new ActionRecord(2L, 1L, FIX, T0.plusMinutes(1)));

        ResponseSequenceAnalysisResponse result = analyse(REPORT_ALL);

        assertThat(result.getTotalActionRecords()).isEqualTo(2);
        assertThat(result.getCollapsedRepeatActions()).isZero();
        assertThat(result.getTransitionAnalysis()).singleElement()
                .satisfies(t -> assertThat(t.getTransitionCount()).isEqualTo(1));
    }

    @Test
    void consecutiveRepeatsOfOneAction_shouldBeOneStep() {
        // Explanation and secure example both send OPEN; a resent request repeats FIX
        action(1, OPEN, 10);
        action(1, OPEN, 11);
        action(1, FIX, 12);
        action(1, FIX, 13);

        ResponseSequenceAnalysisResponse result = analyse(REPORT_ALL);

        assertThat(result.getCollapsedRepeatActions()).isEqualTo(2);
        assertThat(result.getDominantPattern().getActions()).containsExactly(OPEN, FIX);
        assertThat(result.getTransitionAnalysis()).extracting(ActionTransition::getFromAction, ActionTransition::getToAction)
                .containsExactly(org.assertj.core.groups.Tuple.tuple(OPEN, FIX));
    }

    @Test
    void ignoreThenDismiss_shouldStayTwoDifferentActions() {
        action(1, IGNORE, 10);
        action(1, DISMISS, 11);

        assertThat(analyse(REPORT_ALL).getDominantPattern().getActions()).containsExactly(IGNORE, DISMISS);
    }

    @Test
    void eventWithAnActionMissingItsTimestamp_shouldBeLeftOutWhole() {
        action(1, OPEN, 10);
        action(1, FIX, 11);
        action(2, OPEN, 10);
        ownEvents.add(2L);
        records.add(new ActionRecord(nextLogId++, 2L, FIX, null));

        ResponseSequenceAnalysisResponse result = analyse(REPORT_ALL);

        assertThat(result.getTotalEligibleEvents()).isEqualTo(2);
        assertThat(result.getExcludedIncompleteEvents()).isEqualTo(1);
        assertThat(result.getTotalEligibleSequences()).isEqualTo(1);
    }

    // ── Patterns, support and occurrences ─────────────────────────────────────

    @Test
    void researchFixture_shouldGiveTheHandCalculatedPatternsDominantAndTransitions() {
        // e1 OPEN FIX · e2 OPEN FIX · e3 OPEN IGNORE · e4 OPEN IGNORE REOPEN FIX · e5 FIX
        sequence(1, OPEN, FIX);
        sequence(2, OPEN, FIX);
        sequence(3, OPEN, IGNORE);
        sequence(4, OPEN, IGNORE, REOPEN, FIX);
        sequence(5, FIX);

        ResponseSequenceAnalysisResponse result = analyse(DEFAULTS);

        assertThat(result.getAnalysisStatus()).isEqualTo(SequenceAnalysisStatus.ANALYSED);
        assertThat(result.getInsufficientDataReason()).isNull();
        assertThat(result.getTotalEligibleSequences()).isEqualTo(5);
        assertThat(result.getSingleActionSequences()).isEqualTo(1);

        // Patterns in at least 2 of 5 sequences: OPEN FIX (e1, e2) and OPEN IGNORE (e3, e4), 40% each.
        // IGNORE REOPEN, REOPEN FIX and the longer windows occur in e4 only.
        assertThat(result.getFrequentPatterns()).extracting(SequencePattern::getActions)
                .containsExactly(List.of(OPEN, FIX), List.of(OPEN, IGNORE));
        assertThat(result.getFrequentPatterns()).allSatisfy(p -> {
            assertThat(p.getOccurrenceCount()).isEqualTo(2);
            assertThat(p.getSequenceCount()).isEqualTo(2);
            assertThat(p.getSupportPercent()).isEqualTo(40.0);
            assertThat(p.getEligibleSequenceCount()).isEqualTo(5);
        });

        // Complete sequence OPEN FIX occurs twice; every other complete sequence once
        assertThat(result.getDominantPattern().getStatus()).isEqualTo(DominantPatternStatus.FOUND);
        assertThat(result.getDominantPattern().getActions()).containsExactly(OPEN, FIX);
        assertThat(result.getDominantPattern().getOccurrenceCount()).isEqualTo(2);
        assertThat(result.getDominantPattern().getSupportPercent()).isEqualTo(40.0);

        // OPEN leaves 4 times (FIX 2, IGNORE 2); IGNORE once (REOPEN); REOPEN once (FIX)
        assertThat(result.getTransitionAnalysis()).extracting(
                        t -> t.getFromAction() + ">" + t.getToAction() + " " + t.getTransitionCount() + "/"
                                + t.getOutgoingSampleSize() + " " + t.getProbabilityPercent() + " " + t.getSufficientSample())
                .containsExactly(
                        "OPEN>IGNORE 2/4 50.0 false",
                        "OPEN>FIX 2/4 50.0 false",
                        "IGNORE>REOPEN 1/1 100.0 false",
                        "REOPEN>FIX 1/1 100.0 false");
    }

    @Test
    void patternRepeatedInsideOneSequence_shouldCountOccurrencesAndSequencesSeparately() {
        // e1 OPEN IGNORE OPEN IGNORE (IGNORED -> OPENED is allowed) · e2 OPEN IGNORE · e3 FIX
        sequence(1, OPEN, IGNORE, OPEN, IGNORE);
        sequence(2, OPEN, IGNORE);
        sequence(3, FIX);

        SequencePattern openIgnore = pattern(analyse(DEFAULTS), OPEN, IGNORE);

        assertThat(openIgnore.getOccurrenceCount()).isEqualTo(3);
        assertThat(openIgnore.getSequenceCount()).isEqualTo(2);
        assertThat(openIgnore.getSupportPercent()).isEqualTo(66.7);
    }

    @Test
    void patternBelowMinimumSupport_shouldNotBeReported() {
        // OPEN FIX in 2 of 25 sequences = 8%, below 10%; reported once the minimum is 5%
        for (long event = 1; event <= 2; event++) sequence(event, OPEN, FIX);
        for (long event = 3; event <= 25; event++) sequence(event, FIX);

        assertThat(analyse(DEFAULTS).getFrequentPatterns()).isEmpty();
        assertThat(analyse(new Thresholds(3, 2, 5.0, 5)).getFrequentPatterns())
                .singleElement().satisfies(p -> assertThat(p.getSupportPercent()).isEqualTo(8.0));
    }

    @Test
    void patternInOneSequenceOnly_shouldNotBeReported() {
        sequence(1, OPEN, IGNORE, REOPEN, FIX);
        sequence(2, FIX);
        sequence(3, FIX);

        assertThat(analyse(DEFAULTS).getFrequentPatterns()).isEmpty();
    }

    @Test
    void patterns_shouldBeTwoToFiveActionsLong() {
        sequence(1, OPEN, IGNORE, OPEN, IGNORE, OPEN, IGNORE);

        assertThat(analyse(REPORT_ALL).getFrequentPatterns())
                .extracting(SequencePattern::getLength)
                .containsOnly(2, 3, 4, 5);
    }

    @Test
    void lastOccurredAt_shouldBeTheEndOfTheLatestOccurrence() {
        sequence(1, OPEN, FIX);                // minutes 0, 1
        action(2, OPEN, 50);
        action(2, FIX, 55);
        sequence(3, FIX);

        assertThat(pattern(analyse(DEFAULTS), OPEN, FIX).getLastOccurredAt()).isEqualTo(T0.plusMinutes(55));
    }

    // ── Transitions ───────────────────────────────────────────────────────────

    @Test
    void transitionProbability_shouldUseTheSourceActionsOutgoingTransitions() {
        // OPEN -> FIX 3 times, OPEN -> IGNORE once: 75% and 25% of OPEN's 4 outgoing transitions;
        // IGNORE -> FIX once: 100% of IGNORE's 1, not 1 of all 5 transitions
        sequence(1, OPEN, FIX);
        sequence(2, OPEN, FIX);
        sequence(3, OPEN, FIX);
        sequence(4, OPEN, IGNORE, FIX);

        List<ActionTransition> transitions = analyse(DEFAULTS).getTransitionAnalysis();

        assertThat(transitions).extracting(t -> t.getFromAction() + ">" + t.getToAction() + " "
                        + t.getProbabilityPercent() + " n=" + t.getOutgoingSampleSize())
                .containsExactly("OPEN>FIX 75.0 n=4", "OPEN>IGNORE 25.0 n=4", "IGNORE>FIX 100.0 n=1");
        assertThat(transitions).filteredOn(t -> t.getFromAction() == OPEN)
                .extracting(ActionTransition::getProbabilityPercent).containsExactly(75.0, 25.0);
        assertThat(transitions).filteredOn(t -> t.getFromAction() == OPEN)
                .allSatisfy(t -> assertThat(t.getSufficientSample()).isFalse());
    }

    @Test
    void transitionWithEnoughOutgoingSamples_shouldBeMarkedSufficient() {
        for (long event = 1; event <= 5; event++) sequence(event, OPEN, FIX);

        assertThat(analyse(DEFAULTS).getTransitionAnalysis()).singleElement().satisfies(t -> {
            assertThat(t.getOutgoingSampleSize()).isEqualTo(5);
            assertThat(t.getSufficientSample()).isTrue();
        });
    }

    // ── Dominant pattern and insufficient data ────────────────────────────────

    @Test
    void tiedCompleteSequences_shouldGiveNoDominantPattern() {
        sequence(1, OPEN, FIX);
        sequence(2, OPEN, FIX);
        sequence(3, OPEN, IGNORE);
        sequence(4, OPEN, IGNORE);

        ResponseSequenceAnalysisResponse.DominantPattern dominant = analyse(DEFAULTS).getDominantPattern();

        assertThat(dominant.getStatus()).isEqualTo(DominantPatternStatus.INSUFFICIENT_DATA);
        assertThat(dominant.getActions()).isNull();
        assertThat(dominant.getReason()).contains("tied");
    }

    @Test
    void noRecurringCompleteSequence_shouldGiveNoDominantPattern() {
        sequence(1, OPEN, FIX);
        sequence(2, OPEN, IGNORE);
        sequence(3, FIX);

        ResponseSequenceAnalysisResponse result = analyse(DEFAULTS);

        assertThat(result.getAnalysisStatus()).isEqualTo(SequenceAnalysisStatus.ANALYSED);
        assertThat(result.getDominantPattern().getStatus()).isEqualTo(DominantPatternStatus.INSUFFICIENT_DATA);
        assertThat(result.getDominantPattern().getReason()).contains("1 of 3 sequences");
    }

    @Test
    void singleActionCompleteSequence_canBeDominant() {
        sequence(1, FIX);
        sequence(2, FIX);
        sequence(3, OPEN, FIX);

        ResponseSequenceAnalysisResponse.DominantPattern dominant = analyse(DEFAULTS).getDominantPattern();

        assertThat(dominant.getActions()).containsExactly(FIX);
        assertThat(dominant.getSupportPercent()).isEqualTo(66.7);
    }

    @Test
    void noActions_shouldBeInsufficientDataWithNothingReported() {
        ResponseSequenceAnalysisResponse result = analyse(DEFAULTS);

        assertThat(result.getAnalysisStatus()).isEqualTo(SequenceAnalysisStatus.INSUFFICIENT_DATA);
        assertThat(result.getInsufficientDataReason()).isEqualTo("No developer actions are recorded for this developer");
        assertThat(result.getDominantPattern().getStatus()).isEqualTo(DominantPatternStatus.INSUFFICIENT_DATA);
        assertThat(result.getFrequentPatterns()).isEmpty();
        assertThat(result.getTransitionAnalysis()).isEmpty();
    }

    @Test
    void tooFewSequences_shouldReportNoPatternsEvenWhenTheyRepeat() {
        sequence(1, OPEN, FIX);
        sequence(2, OPEN, FIX);

        ResponseSequenceAnalysisResponse result = analyse(DEFAULTS);

        assertThat(result.getAnalysisStatus()).isEqualTo(SequenceAnalysisStatus.INSUFFICIENT_DATA);
        assertThat(result.getInsufficientDataReason()).isEqualTo("Only 2 complete response sequences; at least 3 are needed");
        assertThat(result.getFrequentPatterns()).isEmpty();
        assertThat(result.getTransitionAnalysis()).isEmpty();
        assertThat(result.getTotalEligibleSequences()).isEqualTo(2);
    }

    @Test
    void actionsOnlyOnOtherEvents_shouldExplainWhy() {
        records.add(new ActionRecord(1L, 99L, OPEN, T0));

        assertThat(analyse(DEFAULTS).getInsufficientDataReason())
                .isEqualTo("None of the 1 recorded actions belongs to one of the developer's own security events");
    }

    @Test
    void invalidThresholds_shouldBeRejected() {
        assertThatThrownBy(() -> new Thresholds(0, 2, 10.0, 5)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Thresholds(3, 2, 101.0, 5)).isInstanceOf(IllegalArgumentException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ResponseSequenceAnalysisResponse analyse(Thresholds thresholds) {
        return ResponseSequenceAnalysis.analyse(1L, records, ownEvents, thresholds);
    }

    /** One action on an owned event, {@code minute} minutes after T0. */
    private void action(long eventId, BehaviourAction action, int minute) {
        ownEvents.add(eventId);
        records.add(new ActionRecord(nextLogId++, eventId, action, T0.plusMinutes(minute)));
    }

    /** Actions on one owned event, one minute apart, in the given order. */
    private void sequence(long eventId, BehaviourAction... actions) {
        for (int i = 0; i < actions.length; i++) {
            action(eventId, actions[i], i);
        }
    }

    private static SequencePattern pattern(ResponseSequenceAnalysisResponse result, BehaviourAction... actions) {
        return result.getFrequentPatterns().stream()
                .filter(p -> p.getActions().equals(List.of(actions)))
                .findFirst()
                .orElseThrow(() -> new AssertionError("pattern not reported: " + List.of(actions)));
    }
}
