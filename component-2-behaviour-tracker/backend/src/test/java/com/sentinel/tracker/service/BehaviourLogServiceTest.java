package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.impl.BehaviourLogServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
    private SecurityEventRepository securityEventRepository;

    @InjectMocks
    private BehaviourLogServiceImpl behaviourLogService;

    private Developer developer;
    private SecurityEvent securityEvent;
    private BehaviourLog behaviourLog;

    @BeforeEach
    void setUp() {
        developer = Developer.builder()
                .id(1L)
                .developerIdentifier("dev-001")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        securityEvent = SecurityEvent.builder()
                .id(10L)
                .developer(developer)
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserService.java")
                .lineNumber(42)
                .message("SQL injection")
                .detectedAt(LocalDateTime.now())
                .currentStatus(SecurityEventStatus.DETECTED)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        behaviourLog = BehaviourLog.builder()
                .id(100L)
                .developer(developer)
                .securityEvent(securityEvent)
                .actionType(BehaviourAction.OPEN)
                .timestamp(LocalDateTime.now())
                .createdAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("createBehaviourLog – should create log with valid developer and security event")
    void createBehaviourLog_shouldCreateSuccessfully() {
        CreateBehaviourLogRequest request = new CreateBehaviourLogRequest();
        request.setDeveloperId(1L);
        request.setSecurityEventId(10L);
        request.setActionType(BehaviourAction.OPEN);

        when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
        when(securityEventRepository.findById(10L)).thenReturn(Optional.of(securityEvent));
        when(behaviourLogRepository.save(any(BehaviourLog.class))).thenReturn(behaviourLog);

        BehaviourLogResponse response = behaviourLogService.createBehaviourLog(request);

        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(100L);
        assertThat(response.getActionType()).isEqualTo(BehaviourAction.OPEN);
        assertThat(response.getDeveloperId()).isEqualTo(1L);
        assertThat(response.getSecurityEventId()).isEqualTo(10L);
    }

    @Test
    @DisplayName("createBehaviourLog – should throw when developer not found")
    void createBehaviourLog_shouldThrowWhenDeveloperNotFound() {
        CreateBehaviourLogRequest request = new CreateBehaviourLogRequest();
        request.setDeveloperId(999L);
        request.setActionType(BehaviourAction.IGNORE);

        when(developerRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> behaviourLogService.createBehaviourLog(request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("999");

        verify(behaviourLogRepository, never()).save(any());
    }

    @Test
    @DisplayName("createBehaviourLog – should create log without security event")
    void createBehaviourLog_shouldCreateWithoutSecurityEvent() {
        CreateBehaviourLogRequest request = new CreateBehaviourLogRequest();
        request.setDeveloperId(1L);
        request.setActionType(BehaviourAction.FIX);
        // securityEventId is intentionally null

        BehaviourLog logWithoutEvent = BehaviourLog.builder()
                .id(101L)
                .developer(developer)
                .securityEvent(null)
                .actionType(BehaviourAction.FIX)
                .timestamp(LocalDateTime.now())
                .createdAt(LocalDateTime.now())
                .build();

        when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
        when(behaviourLogRepository.save(any(BehaviourLog.class))).thenReturn(logWithoutEvent);

        BehaviourLogResponse response = behaviourLogService.createBehaviourLog(request);

        assertThat(response.getSecurityEventId()).isNull();
        assertThat(response.getActionType()).isEqualTo(BehaviourAction.FIX);
    }
}
