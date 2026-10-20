package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.AccessDeniedException;
import com.sentinel.tracker.exception.ResourceNotFoundException;
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
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the rules of {@link DeveloperInteractionServiceImpl#createInteraction}
 * (TASKS P1-3 step 1): lock, response time, check order, not-found cases and the history row.
 */
@ExtendWith(MockitoExtension.class)
class DeveloperInteractionServiceRulesTest {

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

    private Developer owner;
    private SecurityEvent event;

    @BeforeEach
    void setUp() {
        owner = Developer.builder().id(1L).developerIdentifier("octocat").build();
        event = SecurityEvent.builder()
                .id(10L)
                .developer(owner)
                .vulnerabilityType("XSS")
                .severity(Severity.MEDIUM)
                .fileName("view.js")
                .lineNumber(7)
                .message("Unescaped output")
                .detectedAt(LocalDateTime.of(2026, 10, 20, 10, 0, 0))
                .build();
    }

    @Test
    void createInteraction_shouldLoadTheEventWithTheRowLock() {
        stubOwnerAndEvent();
        stubLogSave();

        interactionService.createInteraction(request(1L, BehaviourAction.OPEN, null));

        verify(securityEventRepository).findByIdForUpdate(10L);
        verify(securityEventRepository, never()).findById(anyLong());
    }

    @Test
    void createInteraction_withActionTimestamp_shouldComputeResponseTimeFromIt() {
        stubOwnerAndEvent();
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(
                request(1L, BehaviourAction.FIX, LocalDateTime.of(2026, 10, 20, 10, 15, 30)));

        assertThat(response.getTimeSinceDetectionSeconds()).isEqualTo(930L);
        assertThat(response.getActionTimestamp()).isEqualTo(LocalDateTime.of(2026, 10, 20, 10, 15, 30));
    }

    @Test
    void createInteraction_withoutActionTimestamp_shouldUseNow() {
        event.setDetectedAt(LocalDateTime.now().minusMinutes(5));
        stubOwnerAndEvent();
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(
                request(1L, BehaviourAction.OPEN, null));

        assertThat(response.getActionTimestamp()).isCloseTo(LocalDateTime.now(), within(5, ChronoUnit.SECONDS));
        assertThat(response.getTimeSinceDetectionSeconds()).isBetween(295L, 305L);
    }

    @Test
    void createInteraction_transition_shouldWriteHistoryWithFromToTimeAndActor() {
        event.setCurrentStatus(SecurityEventStatus.OPENED);
        stubOwnerAndEvent();
        stubLogSave();
        LocalDateTime at = LocalDateTime.of(2026, 10, 20, 10, 20, 0, 123_456_789);

        interactionService.createInteraction(request(1L, BehaviourAction.IGNORE, at));

        ArgumentCaptor<VulnerabilityLifecycleHistory> captor = ArgumentCaptor.forClass(VulnerabilityLifecycleHistory.class);
        verify(lifecycleHistoryRepository).save(captor.capture());
        VulnerabilityLifecycleHistory row = captor.getValue();
        assertThat(row.getSecurityEvent()).isSameAs(event);
        assertThat(row.getPreviousStatus()).isEqualTo(SecurityEventStatus.OPENED);
        assertThat(row.getNewStatus()).isEqualTo(SecurityEventStatus.IGNORED);
        // Stored at microsecond precision (P2-9), so it reads back identically from PostgreSQL
        assertThat(row.getChangedAt()).isEqualTo(at.truncatedTo(ChronoUnit.MICROS));
        assertThat(row.getChangedBy()).isEqualTo("octocat");
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.IGNORED);
        verify(securityEventRepository).save(event);
    }

    @Test
    void createInteraction_dismiss_shouldBeLoggedAsDismissButMoveToIgnored() {
        stubOwnerAndEvent();
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(
                request(1L, BehaviourAction.DISMISS, null));

        assertThat(response.getAction()).isEqualTo(BehaviourAction.DISMISS);
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.IGNORED);
    }

    @Test
    void createInteraction_otherDeveloper_shouldThrow403BeforeTheTransitionCheck() {
        Developer intruder = Developer.builder().id(2L).developerIdentifier("intruder").build();
        event.setCurrentStatus(SecurityEventStatus.FIXED);
        when(developerRepository.findById(2L)).thenReturn(Optional.of(intruder));
        when(securityEventRepository.findByIdForUpdate(10L)).thenReturn(Optional.of(event));

        // OPEN on FIXED would be a 409; the ownership check must win
        assertThatThrownBy(() -> interactionService.createInteraction(request(2L, BehaviourAction.OPEN, null)))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Developer 2 is not allowed to act on security event 10");

        verifyNothingWritten();
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.FIXED);
    }

    @Test
    void createInteraction_unknownDeveloper_shouldThrow404WithoutLoadingTheEvent() {
        when(developerRepository.findById(1L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> interactionService.createInteraction(request(1L, BehaviourAction.OPEN, null)))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("Developer not found with id: '1'");

        verifyNoInteractions(securityEventRepository, behaviourLogRepository, lifecycleHistoryRepository);
    }

    @Test
    void createInteraction_unknownEvent_shouldThrow404AndWriteNothing() {
        when(developerRepository.findById(1L)).thenReturn(Optional.of(owner));
        when(securityEventRepository.findByIdForUpdate(10L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> interactionService.createInteraction(request(1L, BehaviourAction.OPEN, null)))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessage("Security event not found with id: '10'");

        verifyNothingWritten();
    }

    @Test
    void createInteraction_shouldStoreSessionSourceAndMetadataAsSent() {
        stubOwnerAndEvent();
        stubLogSave();
        CreateDeveloperInteractionRequest request = request(1L, BehaviourAction.OPEN, null);
        request.setSessionId("SESSION-1");
        request.setSource("VSCODE");
        request.setMetadata("{\"extensionAction\":\"SECURE_EXAMPLE_VIEWED\",\"confidence\":0.8}");

        interactionService.createInteraction(request);

        ArgumentCaptor<BehaviourLog> captor = ArgumentCaptor.forClass(BehaviourLog.class);
        verify(behaviourLogRepository).save(captor.capture());
        assertThat(captor.getValue().getSessionId()).isEqualTo("SESSION-1");
        assertThat(captor.getValue().getSource()).isEqualTo("VSCODE");
        assertThat(captor.getValue().getContextMetadata())
                .isEqualTo("{\"extensionAction\":\"SECURE_EXAMPLE_VIEWED\",\"confidence\":0.8}");
        assertThat(captor.getValue().getDeveloper()).isSameAs(owner);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubOwnerAndEvent() {
        when(developerRepository.findById(1L)).thenReturn(Optional.of(owner));
        when(securityEventRepository.findByIdForUpdate(10L)).thenReturn(Optional.of(event));
    }

    private void stubLogSave() {
        when(behaviourLogRepository.save(any(BehaviourLog.class))).thenAnswer(inv -> {
            BehaviourLog log = inv.getArgument(0);
            log.setId(100L);
            return log;
        });
    }

    private void verifyNothingWritten() {
        verify(behaviourLogRepository, never()).save(any());
        verify(securityEventRepository, never()).save(any());
        verify(lifecycleHistoryRepository, never()).save(any());
    }

    private static CreateDeveloperInteractionRequest request(Long developerId, BehaviourAction action,
                                                             LocalDateTime actionTimestamp) {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        request.setDeveloperId(developerId);
        request.setSecurityEventId(10L);
        request.setAction(action);
        request.setActionTimestamp(actionTimestamp);
        return request;
    }
}
