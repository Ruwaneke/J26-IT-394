package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.GitHubAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Implementation of {@link GitHubAuthService}.
 *
 * Strategy:
 * 1. Look up Developer by githubId  → return existing (refresh profile fields).
 * 2. No match → look up by username (developerIdentifier) and link githubId.
 * 3. Still no match → create a brand-new Developer record.
 *
 * Phase 01 / 02 / 03 logic is completely untouched.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class GitHubAuthServiceImpl implements GitHubAuthService {

    private final DeveloperRepository developerRepository;

    @Override
    public DeveloperResponse authenticateWithGitHub(GitHubAuthRequest request) {
        log.info("GitHub auth request for githubId={}, username={}",
                request.getGithubId(), request.getUsername());

        // ── Step 1: locate by githubId (fastest path for returning users) ──────
        Optional<Developer> byGithubId = developerRepository.findByGithubId(request.getGithubId());
        if (byGithubId.isPresent()) {
            Developer existing = byGithubId.get();
            existing = refreshProfile(existing, request);
            Developer saved = developerRepository.save(existing);
            log.info("Returning existing developer id={} (matched by githubId)", saved.getId());
            return DeveloperResponse.from(saved);
        }

        // ── Step 2: locate by username / developerIdentifier (legacy records) ─
        Optional<Developer> byUsername = developerRepository
                .findByDeveloperIdentifier(request.getUsername());
        if (byUsername.isPresent()) {
            Developer existing = byUsername.get();
            existing = refreshProfile(existing, request);
            Developer saved = developerRepository.save(existing);
            log.info("Linked githubId to existing developer id={} (matched by username)", saved.getId());
            return DeveloperResponse.from(saved);
        }

        // ── Step 3: create a new Developer record ─────────────────────────────
        Developer newDeveloper = Developer.builder()
                .developerIdentifier(request.getUsername())
                .githubId(request.getGithubId())
                .githubUsername(request.getUsername())
                .email(request.getEmail())
                .build();

        Developer saved = developerRepository.save(newDeveloper);
        log.info("Created new developer id={} for githubId={}", saved.getId(), request.getGithubId());
        return DeveloperResponse.from(saved);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Refresh mutable GitHub profile fields on an existing Developer record.
     * The developerIdentifier and id are never overwritten.
     */
    private Developer refreshProfile(Developer developer, GitHubAuthRequest request) {
        developer.setGithubId(request.getGithubId());
        developer.setGithubUsername(request.getUsername());
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            developer.setEmail(request.getEmail());
        }
        return developer;
    }
}
