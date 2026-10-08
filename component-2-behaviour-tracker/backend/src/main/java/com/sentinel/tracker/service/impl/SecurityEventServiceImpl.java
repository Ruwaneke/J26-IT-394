package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.SecurityEventResponse;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.SecurityEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of {@link SecurityEventService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class SecurityEventServiceImpl implements SecurityEventService {

    private final SecurityEventRepository securityEventRepository;
    private final DeveloperRepository developerRepository;

    @Override
    @Transactional
    public SecurityEventResponse createSecurityEvent(CreateSecurityEventRequest request) {
        log.info("Creating security event for developer id: {}", request.getDeveloperId());

        Developer developer = developerRepository.findById(request.getDeveloperId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Developer", "id", request.getDeveloperId()));

        LocalDateTime detectedAt = request.getDetectedAt() != null
                ? request.getDetectedAt()
                : LocalDateTime.now();

        SecurityEvent event = SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType(request.getVulnerabilityType())
                .severity(request.getSeverity())
                .fileName(request.getFileName())
                .lineNumber(request.getLineNumber())
                .message(request.getMessage())
                .detectedAt(detectedAt)
                .currentStatus(SecurityEventStatus.DETECTED)
                .build();

        SecurityEvent saved = securityEventRepository.save(event);
        log.info("SecurityEvent created with id: {}", saved.getId());
        return SecurityEventResponse.from(saved);
    }

    @Override
    public SecurityEventResponse getSecurityEventById(Long id) {
        SecurityEvent event = securityEventRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Security event", "id", id));
        return SecurityEventResponse.from(event);
    }

    @Override
    public List<SecurityEventResponse> getAllSecurityEvents() {
        return securityEventRepository.findAll().stream()
                .map(SecurityEventResponse::from)
                .collect(Collectors.toList());
    }

    @Override
    public List<SecurityEventResponse> getSecurityEventsByDeveloper(Long developerId) {
        // Validate developer exists
        if (!developerRepository.existsById(developerId)) {
            throw new ResourceNotFoundException("Developer", "id", developerId);
        }
        return securityEventRepository.findByDeveloperId(developerId).stream()
                .map(SecurityEventResponse::from)
                .collect(Collectors.toList());
    }
}
