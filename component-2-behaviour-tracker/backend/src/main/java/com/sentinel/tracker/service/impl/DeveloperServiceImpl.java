package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.CreateDeveloperRequest;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.exception.DuplicateResourceException;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.DeveloperService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of {@link DeveloperService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class DeveloperServiceImpl implements DeveloperService {

    private final DeveloperRepository developerRepository;

    @Override
    @Transactional
    public DeveloperResponse createDeveloper(CreateDeveloperRequest request) {
        log.info("Creating developer with identifier: {}", request.getDeveloperIdentifier());

        if (developerRepository.existsByDeveloperIdentifier(request.getDeveloperIdentifier())) {
            throw new DuplicateResourceException(
                    "Developer already exists with identifier: " + request.getDeveloperIdentifier());
        }

        Developer developer = Developer.builder()
                .developerIdentifier(request.getDeveloperIdentifier())
                .build();

        Developer saved = developerRepository.save(developer);
        log.info("Developer created with id: {}", saved.getId());
        return DeveloperResponse.from(saved);
    }

    @Override
    public DeveloperResponse getDeveloperById(Long id) {
        Developer developer = developerRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Developer", "id", id));
        return DeveloperResponse.from(developer);
    }

    @Override
    public List<DeveloperResponse> getAllDevelopers() {
        return developerRepository.findAll().stream()
                .map(DeveloperResponse::from)
                .collect(Collectors.toList());
    }
}
