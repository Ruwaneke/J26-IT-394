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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Phase 02 – Extended unit tests for {@link SecurityEventServiceImpl}.
 *
 * Covers all validation scenarios, default detectedAt generation,
 * developer existence checks, get-by-id, and get-all cases.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventServicePhase02Test {

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private DeveloperRepository developerRepository;

    @InjectMocks
    private SecurityEventServiceImpl securityEventService;

    private Developer developer;

    @BeforeEach
    void setUp() {
        developer = Developer.builder()
                .id(1L)
                .developerIdentifier("dev-phase02")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    // ── createSecurityEvent ───────────────────────────────────────────────────

    @Nested
    @DisplayName("createSecurityEvent")
    class CreateSecurityEvent {

        @Test
        @DisplayName("should create event with DETECTED status and auto-generated detectedAt")
        void shouldCreateWithDetectedStatusAndAutoDetectedAt() {
            CreateSecurityEventRequest request = validRequest();
            request.setDetectedAt(null); // force auto-generation

            SecurityEvent saved = buildSavedEvent(request, null);
            when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
            when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

            SecurityEventResponse response = securityEventService.createSecurityEvent(request);

            assertThat(response).isNotNull();
            assertThat(response.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
            assertThat(response.getDetectedAt()).isNotNull();
            verify(securityEventRepository, times(1)).save(any(SecurityEvent.class));
        }

        @Test
        @DisplayName("should use client-supplied detectedAt when provided")
        void shouldUseClientDetectedAtWhenProvided() {
            LocalDateTime clientTime = LocalDateTime.of(2026, 1, 1, 10, 0, 0);
            CreateSecurityEventRequest request = validRequest();
            request.setDetectedAt(clientTime);

            SecurityEvent saved = buildSavedEvent(request, clientTime);
            when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
            when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

            SecurityEventResponse response = securityEventService.createSecurityEvent(request);

            assertThat(response.getDetectedAt()).isEqualTo(clientTime);
        }

        @Test
        @DisplayName("should always set initial status to DETECTED regardless of input")
        void shouldAlwaysSetStatusToDetected() {
            CreateSecurityEventRequest request = validRequest();

            SecurityEvent saved = buildSavedEvent(request, null);
            saved.setCurrentStatus(SecurityEventStatus.DETECTED);

            when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
            when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

            SecurityEventResponse response = securityEventService.createSecurityEvent(request);

            assertThat(response.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException when developer does not exist")
        void shouldThrowWhenDeveloperNotFound() {
            CreateSecurityEventRequest request = validRequest();
            when(developerRepository.findById(1L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> securityEventService.createSecurityEvent(request))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Developer");

            verify(securityEventRepository, never()).save(any());
        }

        @Test
        @DisplayName("should persist all fields correctly")
        void shouldPersistAllFieldsCorrectly() {
            CreateSecurityEventRequest request = validRequest();
            SecurityEvent saved = buildSavedEvent(request, null);

            when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
            when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

            SecurityEventResponse response = securityEventService.createSecurityEvent(request);

            assertThat(response.getDeveloperId()).isEqualTo(1L);
            assertThat(response.getVulnerabilityType()).isEqualTo("SQL_INJECTION");
            assertThat(response.getSeverity()).isEqualTo(Severity.HIGH);
            assertThat(response.getFileName()).isEqualTo("UserService.java");
            assertThat(response.getLineNumber()).isEqualTo(45);
            assertThat(response.getMessage()).isEqualTo("Possible SQL injection vulnerability");
        }

        @Test
        @DisplayName("should work with all valid severity values")
        void shouldWorkWithAllSeverities() {
            for (Severity severity : Severity.values()) {
                CreateSecurityEventRequest request = validRequest();
                request.setSeverity(severity);

                SecurityEvent saved = buildSavedEvent(request, null);
                saved.setSeverity(severity);

                when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
                when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

                SecurityEventResponse response = securityEventService.createSecurityEvent(request);
                assertThat(response.getSeverity()).isEqualTo(severity);

                clearInvocations(developerRepository, securityEventRepository);
            }
        }

        @Test
        @DisplayName("should handle lineNumber of zero (boundary case)")
        void shouldHandleLineNumberZero() {
            CreateSecurityEventRequest request = validRequest();
            request.setLineNumber(0);

            SecurityEvent saved = buildSavedEvent(request, null);
            saved.setLineNumber(0);

            when(developerRepository.findById(1L)).thenReturn(Optional.of(developer));
            when(securityEventRepository.save(any(SecurityEvent.class))).thenReturn(saved);

            SecurityEventResponse response = securityEventService.createSecurityEvent(request);
            assertThat(response.getLineNumber()).isEqualTo(0);
        }
    }

    // ── getSecurityEventById ──────────────────────────────────────────────────

    @Nested
    @DisplayName("getSecurityEventById")
    class GetSecurityEventById {

        @Test
        @DisplayName("should return event when it exists")
        void shouldReturnEventWhenFound() {
            SecurityEvent event = buildSavedEvent(validRequest(), null);
            when(securityEventRepository.findById(1L)).thenReturn(Optional.of(event));

            SecurityEventResponse response = securityEventService.getSecurityEventById(1L);

            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(10L);
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException when event not found")
        void shouldThrowWhenNotFound() {
            when(securityEventRepository.findById(999L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> securityEventService.getSecurityEventById(999L))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Security event")
                    .hasMessageContaining("999");
        }
    }

    // ── getAllSecurityEvents ───────────────────────────────────────────────────

    @Nested
    @DisplayName("getAllSecurityEvents")
    class GetAllSecurityEvents {

        @Test
        @DisplayName("should return empty list when no events exist")
        void shouldReturnEmptyListWhenNoEvents() {
            when(securityEventRepository.findAll()).thenReturn(List.of());

            List<SecurityEventResponse> responses = securityEventService.getAllSecurityEvents();

            assertThat(responses).isEmpty();
        }

        @Test
        @DisplayName("should return all events")
        void shouldReturnAllEvents() {
            SecurityEvent e1 = buildSavedEvent(validRequest(), null);
            SecurityEvent e2 = buildSavedEvent(validRequest(), null);
            e2.setId(11L);

            when(securityEventRepository.findAll()).thenReturn(List.of(e1, e2));

            List<SecurityEventResponse> responses = securityEventService.getAllSecurityEvents();

            assertThat(responses).hasSize(2);
        }
    }

    // ── getSecurityEventsByDeveloper ──────────────────────────────────────────

    @Nested
    @DisplayName("getSecurityEventsByDeveloper")
    class GetSecurityEventsByDeveloper {

        @Test
        @DisplayName("should return events for the given developer")
        void shouldReturnEventsForDeveloper() {
            SecurityEvent event = buildSavedEvent(validRequest(), null);
            when(developerRepository.existsById(1L)).thenReturn(true);
            when(securityEventRepository.findByDeveloperId(1L)).thenReturn(List.of(event));

            List<SecurityEventResponse> responses = securityEventService.getSecurityEventsByDeveloper(1L);

            assertThat(responses).hasSize(1);
            assertThat(responses.get(0).getDeveloperId()).isEqualTo(1L);
        }

        @Test
        @DisplayName("should throw ResourceNotFoundException when developer not found")
        void shouldThrowWhenDeveloperNotFound() {
            when(developerRepository.existsById(999L)).thenReturn(false);

            assertThatThrownBy(() -> securityEventService.getSecurityEventsByDeveloper(999L))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Developer");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CreateSecurityEventRequest validRequest() {
        CreateSecurityEventRequest req = new CreateSecurityEventRequest();
        req.setDeveloperId(1L);
        req.setVulnerabilityType("SQL_INJECTION");
        req.setSeverity(Severity.HIGH);
        req.setFileName("UserService.java");
        req.setLineNumber(45);
        req.setMessage("Possible SQL injection vulnerability");
        return req;
    }

    private SecurityEvent buildSavedEvent(CreateSecurityEventRequest req, LocalDateTime detectedAt) {
        LocalDateTime now = LocalDateTime.now();
        return SecurityEvent.builder()
                .id(10L)
                .developer(developer)
                .vulnerabilityType(req.getVulnerabilityType())
                .severity(req.getSeverity())
                .fileName(req.getFileName())
                .lineNumber(req.getLineNumber())
                .message(req.getMessage())
                .detectedAt(detectedAt != null ? detectedAt : now)
                .currentStatus(SecurityEventStatus.DETECTED)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }
}
