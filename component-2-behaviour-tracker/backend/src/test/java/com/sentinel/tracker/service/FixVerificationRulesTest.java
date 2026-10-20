package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.FixVerificationStatus;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.AccessDeniedException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import com.sentinel.tracker.service.impl.ClaimOnlyFixVerificationService;
import com.sentinel.tracker.service.impl.DeveloperInteractionServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for claimed versus verified fixes in
 * {@link DeveloperInteractionServiceImpl#createInteraction} (TASKS P1-6). The verification
 * source is a mock returning controlled results, standing in for C1 re-scan results.
 */
@ExtendWith(MockitoExtension.class)
class FixVerificationRulesTest {

    private static final LocalDateTime CLAIMED_AT = LocalDateTime.of(2026, 10, 20, 10, 5, 0);

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
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserDao.java")
                .lineNumber(42)
                .message("Unparameterised query")
                .detectedAt(LocalDateTime.of(2026, 10, 20, 10, 0, 0))
                .build();
        // Lenient: the 403 and default-implementation tests do not load the owner or the event
        lenient().when(developerRepository.findById(1L)).thenReturn(Optional.of(owner));
        lenient().when(securityEventRepository.findByIdForUpdate(10L)).thenReturn(Optional.of(event));
    }

    // ── FIX actions ───────────────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(FixVerificationStatus.class)
    void createInteraction_fix_shouldStoreTheVerificationResultAndStillMoveToFixed(FixVerificationStatus result) {
        when(fixVerificationService.verifyFix(event, CLAIMED_AT)).thenReturn(result);
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(request(BehaviourAction.FIX));

        assertThat(savedLog().getFixVerification()).isEqualTo(result);
        assertThat(response.getFixVerification()).isEqualTo(result);
        // The lifecycle records the claim whatever the verification says
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.FIXED);
        ArgumentCaptor<VulnerabilityLifecycleHistory> history =
                ArgumentCaptor.forClass(VulnerabilityLifecycleHistory.class);
        verify(lifecycleHistoryRepository).save(history.capture());
        assertThat(history.getValue().getPreviousStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(history.getValue().getNewStatus()).isEqualTo(SecurityEventStatus.FIXED);
    }

    @Test
    void createInteraction_fixWithNoVerificationAnswer_shouldBeStoredAsClaimed() {
        when(fixVerificationService.verifyFix(any(), any())).thenReturn(null);
        stubLogSave();

        interactionService.createInteraction(request(BehaviourAction.FIX));

        assertThat(savedLog().getFixVerification()).isEqualTo(FixVerificationStatus.CLAIMED);
    }

    @Test
    void createInteraction_fixOnFixedEvent_shouldStoreTheVerificationWithoutHistory() {
        event.setCurrentStatus(SecurityEventStatus.FIXED);
        when(fixVerificationService.verifyFix(event, CLAIMED_AT)).thenReturn(FixVerificationStatus.VERIFIED);
        stubLogSave();

        interactionService.createInteraction(request(BehaviourAction.FIX));

        assertThat(savedLog().getFixVerification()).isEqualTo(FixVerificationStatus.VERIFIED);
        assertThat(event.getCurrentStatus()).isEqualTo(SecurityEventStatus.FIXED);
        verify(lifecycleHistoryRepository, never()).save(any());
    }

    @Test
    void createInteraction_fixByAnotherDeveloper_shouldBeRejectedBeforeVerification() {
        Developer intruder = Developer.builder().id(2L).developerIdentifier("intruder").build();
        when(developerRepository.findById(2L)).thenReturn(Optional.of(intruder));
        CreateDeveloperInteractionRequest request = request(BehaviourAction.FIX);
        request.setDeveloperId(2L);

        assertThatThrownBy(() -> interactionService.createInteraction(request))
                .isInstanceOf(AccessDeniedException.class);

        verifyNoInteractions(fixVerificationService, behaviourLogRepository);
    }

    // ── Other actions ─────────────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(value = BehaviourAction.class, names = "FIX", mode = EnumSource.Mode.EXCLUDE)
    void createInteraction_nonFixAction_shouldHaveNoFixVerification(BehaviourAction action) {
        // A status every non-FIX action may leave or stay in
        event.setCurrentStatus(action == BehaviourAction.REOPEN ? SecurityEventStatus.FIXED : SecurityEventStatus.DETECTED);
        stubLogSave();

        DeveloperInteractionResponse response = interactionService.createInteraction(request(action));

        assertThat(savedLog().getFixVerification()).isNull();
        assertThat(response.getFixVerification()).isNull();
        verifyNoInteractions(fixVerificationService);
    }

    // ── Default implementation ────────────────────────────────────────────────

    @Test
    void claimOnlyVerification_shouldNeverReportAFixAsVerified() {
        assertThat(new ClaimOnlyFixVerificationService().verifyFix(event, CLAIMED_AT))
                .isEqualTo(FixVerificationStatus.CLAIMED);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CreateDeveloperInteractionRequest request(BehaviourAction action) {
        CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
        request.setSecurityEventId(10L);
        request.setDeveloperId(1L);
        request.setAction(action);
        request.setActionTimestamp(CLAIMED_AT);
        return request;
    }

    private void stubLogSave() {
        when(behaviourLogRepository.save(any(BehaviourLog.class))).thenAnswer(invocation -> {
            BehaviourLog log = invocation.getArgument(0);
            log.setId(100L);
            return log;
        });
    }

    private BehaviourLog savedLog() {
        ArgumentCaptor<BehaviourLog> log = ArgumentCaptor.forClass(BehaviourLog.class);
        verify(behaviourLogRepository).save(log.capture());
        return log.getValue();
    }
}
