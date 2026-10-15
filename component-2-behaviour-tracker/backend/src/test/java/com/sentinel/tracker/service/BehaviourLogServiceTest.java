package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.impl.BehaviourLogServiceImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link BehaviourLogServiceImpl}.
 */
@ExtendWith(MockitoExtension.class)
class BehaviourLogServiceTest {

    @Mock
    private BehaviourLogRepository behaviourLogRepository;

    @Mock
    private DeveloperRepository developerRepository;

    @Mock
    private DeveloperInteractionService developerInteractionService;

    @InjectMocks
    private BehaviourLogServiceImpl behaviourLogService;

    @Test
    @DisplayName("createBehaviourLog – should delegate to DeveloperInteractionService with mapped fields")
    void createBehaviourLog_delegatesToInteractionService() {
        LocalDateTime timestamp = LocalDateTime.of(2026, 10, 8, 10, 0);
        CreateBehaviourLogRequest request = new CreateBehaviourLogRequest();
        request.setDeveloperId(1L);
        request.setSecurityEventId(10L);
        request.setActionType(BehaviourAction.OPEN);
        request.setTimestamp(timestamp);
        request.setContextMetadata("{\"ide\":\"vscode\"}");

        when(developerInteractionService.createInteraction(any())).thenReturn(
                DeveloperInteractionResponse.builder()
                        .id(100L)
                        .developerId(1L)
                        .securityEventId(10L)
                        .action(BehaviourAction.OPEN)
                        .actionTimestamp(timestamp)
                        .timeSinceDetectionSeconds(42L)
                        .metadata("{\"ide\":\"vscode\"}")
                        .build());

        BehaviourLogResponse response = behaviourLogService.createBehaviourLog(request);

        ArgumentCaptor<CreateDeveloperInteractionRequest> captor =
                ArgumentCaptor.forClass(CreateDeveloperInteractionRequest.class);
        verify(developerInteractionService).createInteraction(captor.capture());
        CreateDeveloperInteractionRequest delegated = captor.getValue();
        assertThat(delegated.getDeveloperId()).isEqualTo(1L);
        assertThat(delegated.getSecurityEventId()).isEqualTo(10L);
        assertThat(delegated.getAction()).isEqualTo(BehaviourAction.OPEN);
        assertThat(delegated.getActionTimestamp()).isEqualTo(timestamp);
        assertThat(delegated.getMetadata()).isEqualTo("{\"ide\":\"vscode\"}");

        assertThat(response.getId()).isEqualTo(100L);
        assertThat(response.getActionType()).isEqualTo(BehaviourAction.OPEN);
        assertThat(response.getDeveloperId()).isEqualTo(1L);
        assertThat(response.getSecurityEventId()).isEqualTo(10L);
        assertThat(response.getTimestamp()).isEqualTo(timestamp);
        assertThat(response.getContextMetadata()).isEqualTo("{\"ide\":\"vscode\"}");

        // No direct write path left in this service
        verify(behaviourLogRepository, never()).save(any());
    }

    @Test
    @DisplayName("createBehaviourLog – should propagate not-found errors from the interaction service")
    void createBehaviourLog_shouldThrowWhenDeveloperNotFound() {
        CreateBehaviourLogRequest request = new CreateBehaviourLogRequest();
        request.setDeveloperId(999L);
        request.setSecurityEventId(10L);
        request.setActionType(BehaviourAction.IGNORE);

        when(developerInteractionService.createInteraction(any()))
                .thenThrow(new ResourceNotFoundException("Developer", "id", 999L));

        assertThatThrownBy(() -> behaviourLogService.createBehaviourLog(request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("999");

        verify(behaviourLogRepository, never()).save(any());
    }

    @Test
    @DisplayName("getBehaviourLogById – should still return the legacy representation")
    void getBehaviourLogById_returnsLegacyResponse() {
        Developer developer = Developer.builder().id(1L).developerIdentifier("dev-001").build();
        SecurityEvent event = SecurityEvent.builder().id(10L).developer(developer).build();
        BehaviourLog log = BehaviourLog.builder()
                .id(100L)
                .developer(developer)
                .securityEvent(event)
                .actionType(BehaviourAction.FIX)
                .timestamp(LocalDateTime.now())
                .contextMetadata("meta")
                .build();

        when(behaviourLogRepository.findById(100L)).thenReturn(Optional.of(log));

        BehaviourLogResponse response = behaviourLogService.getBehaviourLogById(100L);

        assertThat(response.getId()).isEqualTo(100L);
        assertThat(response.getActionType()).isEqualTo(BehaviourAction.FIX);
        assertThat(response.getSecurityEventId()).isEqualTo(10L);
        assertThat(response.getContextMetadata()).isEqualTo("meta");
    }
}
