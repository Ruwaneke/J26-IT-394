package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.FixVerificationStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.impl.BehaviourAnalysisServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BehaviourAnalysisServiceTest {

    @Mock
    private DeveloperRepository developerRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private BehaviourLogRepository behaviourLogRepository;

    @InjectMocks
    private BehaviourAnalysisServiceImpl analysisService;

    private Developer developer;
    private List<SecurityEvent> mockEvents;
    private List<BehaviourLog> mockLogs;

    @BeforeEach
    void setUp() {
        developer = new Developer();
        developer.setId(1L);
        developer.setDeveloperIdentifier("test-dev");
        mockEvents = new ArrayList<>();
        mockLogs = new ArrayList<>();
    }

    private SecurityEvent createEvent(Long id, String type, Severity severity) {
        SecurityEvent event = new SecurityEvent();
        event.setId(id);
        event.setVulnerabilityType(type);
        event.setSeverity(severity);
        mockEvents.add(event);
        return event;
    }

    private BehaviourLog createLog(SecurityEvent event, BehaviourAction action, Long timeSinceDetection) {
        BehaviourLog log = new BehaviourLog();
        log.setDeveloper(developer);
        log.setSecurityEvent(event);
        log.setActionType(action);
        log.setTimeSinceDetectionSeconds(timeSinceDetection);
        mockLogs.add(log);
        return log;
    }

    private void prepareMocks() {
        when(developerRepository.existsById(1L)).thenReturn(true);
        when(securityEventRepository.findByDeveloperId(1L)).thenReturn(mockEvents);
        when(behaviourLogRepository.findByDeveloperId(1L)).thenReturn(mockLogs);
    }

    @Test
    void testSecurityResponsive() {
        // High fix rate (100%), High severity fix rate (100%), ignore rate (0%)
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        SecurityEvent e2 = createEvent(2L, "XSS", Severity.MEDIUM);
        SecurityEvent e3 = createEvent(3L, "CSRF", Severity.HIGH);

        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e2, BehaviourAction.FIX, 20L);
        createLog(e3, BehaviourAction.FIX, 15L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getBehaviourClassification()).isEqualTo("SECURITY_RESPONSIVE");
        assertThat(response.getFixRate()).isEqualTo(100.0);
        assertThat(response.getAverageResponseTimeSeconds()).isEqualTo(15.0);
    }

    @Test
    void testSecurityAtRisk() {
        // Ignore rate >= 40%
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        SecurityEvent e2 = createEvent(2L, "XSS", Severity.MEDIUM);
        SecurityEvent e3 = createEvent(3L, "CSRF", Severity.HIGH);

        createLog(e1, BehaviourAction.IGNORE, 5L);
        createLog(e2, BehaviourAction.DISMISS, 5L);
        createLog(e3, BehaviourAction.FIX, 50L); // 2 out of 3 ignored/dismissed = 66% ignore rate

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getBehaviourClassification()).isEqualTo("SECURITY_AT_RISK");
        assertThat(response.getIgnoreRate()).isEqualTo(66.7);
    }

    @Test
    void testRecurringSecurityBehaviour() {
        // Reopen rate >= 30%
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.LOW);
        SecurityEvent e2 = createEvent(2L, "SQL_INJECTION", Severity.LOW);
        SecurityEvent e3 = createEvent(3L, "SQL_INJECTION", Severity.LOW);
        SecurityEvent e4 = createEvent(4L, "XSS", Severity.LOW);

        // 2 reopens out of 4 total events = 50% reopen rate
        createLog(e1, BehaviourAction.REOPEN, 10L);
        createLog(e2, BehaviourAction.REOPEN, 10L);
        createLog(e3, BehaviourAction.OPEN, 10L);
        createLog(e4, BehaviourAction.OPEN, 10L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getBehaviourClassification()).isEqualTo("RECURRING_SECURITY_BEHAVIOUR");
        assertThat(response.getReopenRate()).isEqualTo(50.0);
    }

    @Test
    void testInsufficientData() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.LOW);
        createLog(e1, BehaviourAction.OPEN, 10L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getBehaviourClassification()).isEqualTo("INSUFFICIENT_DATA");
    }

    @Test
    void multipleFixActionsOnSameEvent_countOnce() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        createEvent(2L, "XSS", Severity.HIGH);

        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e1, BehaviourAction.FIX, 20L);
        createLog(e1, BehaviourAction.FIX, 30L);
        createLog(e1, BehaviourAction.OPEN, 5L);
        createLog(e1, BehaviourAction.OPEN, 6L);
        createLog(e1, BehaviourAction.IGNORE, 7L);
        createLog(e1, BehaviourAction.IGNORE, 8L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixedCount()).isEqualTo(1L);
        assertThat(response.getOpenedCount()).isEqualTo(1L);
        assertThat(response.getIgnoredCount()).isEqualTo(1L);
        assertThat(response.getFixRate()).isEqualTo(50.0);
        assertThat(response.getIgnoreRate()).isEqualTo(50.0);
        assertThat(response.getHighSeverityFixRate()).isEqualTo(50.0);
    }

    @Test
    void repeatedOpenLogs_doNotChangeAnyRateOrCount() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        SecurityEvent e2 = createEvent(2L, "XSS", Severity.MEDIUM);
        SecurityEvent e3 = createEvent(3L, "HARDCODED_SECRET", Severity.LOW);
        createLog(e1, BehaviourAction.OPEN, 10L);
        createLog(e1, BehaviourAction.FIX, 60L);
        createLog(e2, BehaviourAction.OPEN, 20L);
        createLog(e3, BehaviourAction.IGNORE, 30L);
        prepareMocks();

        DeveloperBehaviourSummaryResponse before = analysisService.getDeveloperBehaviourSummary(1L);

        // The same-status OPENs that are now accepted (TASKS P1-1)
        createLog(e1, BehaviourAction.OPEN, 15L);
        createLog(e2, BehaviourAction.OPEN, 25L);
        createLog(e2, BehaviourAction.OPEN, 35L);

        DeveloperBehaviourSummaryResponse after = analysisService.getDeveloperBehaviourSummary(1L);

        assertThat(after.getOpenedCount()).isEqualTo(before.getOpenedCount()).isEqualTo(2L);
        assertThat(after.getFixedCount()).isEqualTo(before.getFixedCount());
        assertThat(after.getIgnoredCount()).isEqualTo(before.getIgnoredCount());
        assertThat(after.getFixRate()).isEqualTo(before.getFixRate()).isEqualTo(33.3);
        assertThat(after.getIgnoreRate()).isEqualTo(before.getIgnoreRate()).isEqualTo(33.3);
        assertThat(after.getReopenRate()).isEqualTo(before.getReopenRate());
        assertThat(after.getHighSeverityFixRate()).isEqualTo(before.getHighSeverityFixRate()).isEqualTo(100.0);
        assertThat(after.getBehaviourClassification()).isEqualTo(before.getBehaviourClassification());
    }

    @Test
    void ratesNeverExceed100_evenWithRepeatedActions() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.CRITICAL);

        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e1, BehaviourAction.IGNORE, 10L);
        createLog(e1, BehaviourAction.DISMISS, 10L);
        createLog(e1, BehaviourAction.REOPEN, 10L);
        createLog(e1, BehaviourAction.REOPEN, 10L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixRate()).isEqualTo(100.0);
        assertThat(response.getIgnoreRate()).isEqualTo(100.0);
        assertThat(response.getReopenRate()).isEqualTo(100.0);
        assertThat(response.getHighSeverityFixRate()).isEqualTo(100.0);
    }

    @Test
    void actionsWithoutOrOutsideOwnEvents_areNotCounted() {
        createEvent(1L, "SQL_INJECTION", Severity.HIGH);

        SecurityEvent otherDevelopersEvent = new SecurityEvent();
        otherDevelopersEvent.setId(99L);
        otherDevelopersEvent.setSeverity(Severity.HIGH);

        createLog(otherDevelopersEvent, BehaviourAction.FIX, 10L);
        createLog(null, BehaviourAction.FIX, null);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixedCount()).isZero();
        assertThat(response.getFixRate()).isEqualTo(0.0);
        assertThat(response.getHighSeverityFixRate()).isEqualTo(0.0);
    }

    @Test
    void zeroEvents_returnsZeroRatesAndNoAutomaticHighSeverityScore() {
        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getTotalSecurityEvents()).isZero();
        assertThat(response.getFixedCount()).isZero();
        assertThat(response.getOpenedCount()).isZero();
        assertThat(response.getIgnoredCount()).isZero();
        assertThat(response.getFixRate()).isEqualTo(0.0);
        assertThat(response.getIgnoreRate()).isEqualTo(0.0);
        assertThat(response.getReopenRate()).isEqualTo(0.0);
        assertThat(response.getHighSeverityFixRate()).isNull();
        assertThat(response.getBehaviourClassification()).isEqualTo("INSUFFICIENT_DATA");
    }

    @Test
    void noHighSeverityEvents_highSeverityFixRateIsNotApplicable() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.LOW);
        SecurityEvent e2 = createEvent(2L, "XSS", Severity.MEDIUM);
        SecurityEvent e3 = createEvent(3L, "CSRF", Severity.LOW);

        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e2, BehaviourAction.FIX, 10L);
        createLog(e3, BehaviourAction.FIX, 10L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getHighSeverityFixRate()).isNull();
        assertThat(response.getFixRate()).isEqualTo(100.0);
        // Not penalised or rewarded for missing high-severity events
        assertThat(response.getBehaviourClassification()).isEqualTo("SECURITY_RESPONSIVE");
    }

    @Test
    void mixedSeverityEvents_highSeverityFixRateUsesOnlyHighAndCritical() {
        SecurityEvent high = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        SecurityEvent critical = createEvent(2L, "COMMAND_INJECTION", Severity.CRITICAL);
        createEvent(3L, "HARDCODED_SECRET", Severity.HIGH);
        SecurityEvent medium = createEvent(4L, "XSS", Severity.MEDIUM);
        SecurityEvent low = createEvent(5L, "WEAK_HASH", Severity.LOW);

        createLog(high, BehaviourAction.FIX, 10L);
        createLog(high, BehaviourAction.FIX, 12L);   // repeat on same event – counted once
        createLog(critical, BehaviourAction.FIX, 20L);
        createLog(medium, BehaviourAction.FIX, 30L);
        createLog(low, BehaviourAction.FIX, 40L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixedCount()).isEqualTo(4L);
        assertThat(response.getFixRate()).isEqualTo(80.0);              // 4 of 5 events
        assertThat(response.getHighSeverityFixRate()).isEqualTo(66.7);  // 2 of 3 HIGH/CRITICAL events
        assertThat(response.getBehaviourClassification()).isEqualTo("SECURITY_NEUTRAL");
    }

    @Test
    void claimedFixes_countAsFixesButNotAsVerifiedFixes() {
        // 4 events. e1: FIX verified. e2: FIX claimed, then FIX verified (counts once).
        // e3: FIX claimed only. e4: FIX still vulnerable. Fixes claimed on 4 of 4, verified on 2 of 4.
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        SecurityEvent e2 = createEvent(2L, "XSS", Severity.MEDIUM);
        SecurityEvent e3 = createEvent(3L, "XSS", Severity.LOW);
        SecurityEvent e4 = createEvent(4L, "HARDCODED_SECRET", Severity.HIGH);

        createLog(e1, BehaviourAction.FIX, 10L).setFixVerification(FixVerificationStatus.VERIFIED);
        createLog(e2, BehaviourAction.FIX, 10L).setFixVerification(FixVerificationStatus.CLAIMED);
        createLog(e2, BehaviourAction.FIX, 20L).setFixVerification(FixVerificationStatus.VERIFIED);
        createLog(e3, BehaviourAction.FIX, 10L).setFixVerification(FixVerificationStatus.CLAIMED);
        createLog(e4, BehaviourAction.FIX, 10L).setFixVerification(FixVerificationStatus.STILL_VULNERABLE);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixedCount()).isEqualTo(4L);
        assertThat(response.getFixRate()).isEqualTo(100.0);
        assertThat(response.getVerifiedFixCount()).isEqualTo(2L);
        assertThat(response.getVerifiedFixRate()).isEqualTo(50.0);
        // The classification still uses claimed fixes (unchanged until agreed otherwise)
        assertThat(response.getHighSeverityFixRate()).isEqualTo(100.0);
        assertThat(response.getBehaviourClassification()).isEqualTo("SECURITY_RESPONSIVE");
    }

    @Test
    void noVerifiedFixes_givesZeroVerifiedFixCountAndRate() {
        SecurityEvent e1 = createEvent(1L, "SQL_INJECTION", Severity.HIGH);
        createEvent(2L, "XSS", Severity.MEDIUM);
        createEvent(3L, "XSS", Severity.MEDIUM);

        // A legacy FIX log without a verification value is not a verified fix
        createLog(e1, BehaviourAction.FIX, 10L);
        createLog(e1, BehaviourAction.REOPEN, 20L);

        prepareMocks();

        DeveloperBehaviourSummaryResponse response = analysisService.getDeveloperBehaviourSummary(1L);
        assertThat(response.getFixRate()).isEqualTo(33.3);
        assertThat(response.getVerifiedFixCount()).isZero();
        assertThat(response.getVerifiedFixRate()).isEqualTo(0.0);
    }
}
