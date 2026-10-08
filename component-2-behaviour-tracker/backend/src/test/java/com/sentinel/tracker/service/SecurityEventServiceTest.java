package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.SecurityEventResponse;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.impl.SecurityEventServiceImpl;
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
 * Unit tests for {@link SecurityEventServiceImpl}.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventServiceTest {

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private DeveloperRepository developerRepository;

    @InjectMocks
    private SecurityEventServiceImpl securityEventService;

    private Developer developer;
    private SecurityEvent securityEvent;

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
                .message("Potential SQL injection at line 42")
                .detectedAt(LocalDateTime.now())
                .currentStatus(SecurityEventStatus.DETECTED)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    @Test
    @DisplayName("createSecurityEvent – should create event with DETECTED status")
    void createSecurityEvent_shouldCreateWithDetectedStatus() {
        // Arrange
        CreateSecurityEventRequest request = new CreateSecurityEventRequest();
        request.setDeveloperId(1L);
        request.setVulnerabilityType("SQL_INJECTION");
        request.setSeverity(Severity.HIGH);
        request.setFileName("UserService.java");
        request.setLineNumber(42);
        request.setMessage("Potential SQL injection at line 42");

        when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
        when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(securityEvent);

        // Act
        SecurityEventResponse response = securityEventService.createSecurityEvent(request);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(10L);
        assertThat(response.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(response.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(response.getDeveloperId()).isEqualTo(1L);
        verify(securityEventRepository, times(1)).save(any(SecurityEvent.class));
    }

    @Test
    @DisplayName("createSecurityEvent – should throw when developer not found")
    void createSecurityEvent_shouldThrowWhenDeveloperNotFound() {
        CreateSecurityEventRequest request = new CreateSecurityEventRequest();
        request.setDeveloperId(999L);
        request.setVulnerabilityType("XSS");
        request.setSeverity(Severity.MEDIUM);
        request.setFileName("view.html");
        request.setLineNumber(10);
        request.setMessage("XSS vulnerability");

        when(developerRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> securityEventService.createSecurityEvent(request))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("999");

        verify(securityEventRepository, never()).save(any());
    }

    @Test
    @DisplayName("getSecurityEventById – should throw when event not found")
    void getSecurityEventById_shouldThrowWhenNotFound() {
        when(securityEventRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> securityEventService.getSecurityEventById(999L))
                .isInstanceOf(ResourceNotFoundException.class);
    }
}
