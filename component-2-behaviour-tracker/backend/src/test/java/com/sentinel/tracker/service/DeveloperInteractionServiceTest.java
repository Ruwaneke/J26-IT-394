package com.sentinel.tracker.service;

import com.sentinel.tracker.analysis.LifecycleHashChain;
import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.InvalidStatusTransitionException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import com.sentinel.tracker.service.impl.DeveloperInteractionServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DeveloperInteractionServiceImpl}: same-status actions versus real
 * status transitions.
 */
@ExtendWith(MockitoExtension.class)
class DeveloperInteractionServiceTest {

    @Mock
    private BehaviourLogRepository behaviourLogRepository;

    @Mock
    private DeveloperRepository developerRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    @Mock
    private FixVerificationService fixVerificationService;

    @InjectMocks
    private DeveloperInteractionServiceImpl interactionService;

    private Developer developer;
    private SecurityEvent event;

    @BeforeEach
    void setUp() {
        developer = Developer.builder().id(1L).developerIdentifier("octocat").build();
        event = SecurityEvent.builder()
                .id(10L)
                .developer(developer)
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserDao.java")
                .lineNumber(42)
                .message("Unparameterised query")
                .detectedAt(LocalDateTime.of(2026, 10, 20, 10, 0, 0))
                .build();

        when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
        when(securityEventRepository.findByIdForUpdate(10L)).thenReturn(Optional.of(event));
    }

    // ── Same-status actions ───────────────────────────────────────────────────

    @Test
    void createInteraction_secondOpen_shouldLogWithoutStatusChangeOrHistory() {
        event.setCurrentStatus(SecurityEventStatus.OPENED);
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(
                request(BehaviourAction.OPEN, LocalDateTime.of(2026, 10, 20, 10, 2, 0)));

        assertThat(response.getAction()).isEqualTo(BehaviourAction.OPEN);
        assertThat(response.getTimeSinceDetectionSeconds()).isEqualTo(120L);
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.OPENED);
        verify(behaviourLogRepository).save(any(BehaviourLog.class));
        verify(securityEventRepository, never()).save(any());
        verify(lifecycleHistoryRepository, never()).save(any());
    }

    @Test
    void createInteraction_dismissOnIgnored_shouldLogWithoutStatusChangeOrHistory() {
        event.setCurrentStatus(SecurityEventStatus.IGNORED);
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(
                request(BehaviourAction.DISMISS, null));

        assertThat(response.getAction()).isEqualTo(BehaviourAction.DISMISS);
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.IGNORED);
        verify(behaviourLogRepository).save(any(BehaviourLog.class));
        verify(securityEventRepository, never()).save(any());
        verify(lifecycleHistoryRepository, never()).save(any());
    }

    // ── Real transitions ──────────────────────────────────────────────────────

    @Test
    void createInteraction_validTransition_shouldChangeStatusAndWriteOneHistoryRow() {
        event.setCurrentStatus(SecurityEventStatus.DETECTED);
        stubLogSave();
        LocalDateTime actionTime = LocalDateTime.of(2026, 10, 20, 10, 5, 0);

        interactionService.createInteraction(request(BehaviourAction.OPEN, actionTime));

        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.OPENED);
        verify(securityEventRepository).save(event);
        ArgumentCaptor<VulnerabilityLifecycleHistory> captor =
                ArgumentCaptor.forClass(VulnerabilityLifecycleHistory.class);
        verify(lifecycleHistoryRepository).save(captor.capture());
        assertThat(captor.getValue().getPreviousStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(captor.getValue().getNewStatus()).isEqualTo(SecurityEventStatus.OPENED);
        assertThat(captor.getValue().getChangedAt()).isEqualTo(actionTime);
        assertThat(captor.getValue().getChangedBy()).isEqualTo("octocat");
    }

    @Test
    void createInteraction_validTransition_shouldChainHistoryRowToLatestEntry() {
        event.setCurrentStatus(SecurityEventStatus.DETECTED);
        stubLogSave();
        String latestEntryHash = "c".repeat(64);
        when(lifecycleHistoryRepository.findFirstBySecurityEventIdOrderByIdDesc(10L)).thenReturn(Optional.of(
                VulnerabilityLifecycleHistory.builder().entryHash(latestEntryHash).build()));

        interactionService.createInteraction(request(BehaviourAction.OPEN, LocalDateTime.of(2026, 10, 20, 10, 5, 0)));

        ArgumentCaptor<VulnerabilityLifecycleHistory> captor =
                ArgumentCaptor.forClass(VulnerabilityLifecycleHistory.class);
        verify(lifecycleHistoryRepository).save(captor.capture());
        VulnerabilityLifecycleHistory saved = captor.getValue();
        assertThat(saved.getPrevHash()).isEqualTo(latestEntryHash);
        assertThat(saved.getEntryHash()).isEqualTo(LifecycleHashChain.computeEntryHash(latestEntryHash, saved));
    }

    @Test
    void createInteraction_openOnFixed_shouldThrowAndStoreNothing() {
        event.setCurrentStatus(SecurityEventStatus.FIXED);

        assertThatThrownBy(() -> interactionService.createInteraction(request(BehaviourAction.OPEN, null)))
                .isInstanceOf(InvalidStatusTransitionException.class)
                .hasMessageContaining("cannot move from FIXED to OPENED");

        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.FIXED);
        verify(behaviourLogRepository, never()).save(any());
        verify(securityEventRepository, never()).save(any());
        verify(lifecycleHistoryRepository, never()).save(any());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CreateDeveloperInteractionRequest request(BehaviourAction action, LocalDateTime actionTimestamp) {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        request.setDeveloperId(1L);
        request.setSecurityEventId(10L);
        request.setAction(action);
        request.setActionTimestamp(actionTimestamp);
        return request;
    }

    private void stubLogSave() {
        when(behaviourLogRepository.save(any(BehaviourLog.class))).thenAnswer(invocation -> {
            BehaviourLog log = invocation.getArgument(0);
            log.setId(100L);
            return log;
        });
    }
}
