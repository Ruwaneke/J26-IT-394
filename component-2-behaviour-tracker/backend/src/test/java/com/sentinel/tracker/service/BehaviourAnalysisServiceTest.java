package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
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
}
