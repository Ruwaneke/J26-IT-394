package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.client.GitHubApiClient;
import com.sentinel.tracker.client.GitHubUserProfile;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.exception.DuplicateResourceException;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.GitHubAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Implementation of {@link GitHubAuthService}.
 *
 * The client sends only a GitHub access token. The identity (id, login, email)
 * is always taken from GitHub's {@code GET /user} response, never from the client.
 *
 * Strategy:
 * 1. Look up Developer by verified githubId → return existing (refresh profile fields).
 * 2. No match → look up a legacy Developer (no githubId yet) whose developerIdentifier
 *    equals the verified login, and link it.
 * 3. Still no match → create a brand-new Developer record.
 *
 * Not annotated with @Transactional so that no database connection is held
 * while waiting on the GitHub API; each repository call runs in its own transaction.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GitHubAuthServiceImpl implements GitHubAuthService {

    private final DeveloperRepository developerRepository;
    private final GitHubApiClient gitHubApiClient;

    @Override
    public DeveloperResponse authenticateWithGitHub(GitHubAuthRequest request) {
        GitHubUserProfile profile = gitHubApiClient.fetchAuthenticatedUser(request.getGithubAccessToken());
        String githubId = String.valueOf(profile.getId());
        String login = profile.getLogin();

        log.info("GitHub auth verified for githubId={}, login={}", githubId, login);

        // ── Step 1: locate by verified githubId (returning users) ─────────────
        Optional<Developer> byGithubId = developerRepository.findByGithubId(githubId);
        if (byGithubId.isPresent()) {
            Developer saved = developerRepository.save(refreshProfile(byGithubId.get(), githubId, profile));
            log.info("Returning existing developer id={} (matched by githubId)", saved.getId());
            return DeveloperResponse.from(saved);
        }

        // ── Step 2: link a legacy record created before GitHub auth ───────────
        Optional<Developer> byLogin = developerRepository.findByDeveloperIdentifier(login);
        if (byLogin.isPresent()) {
            Developer existing = byLogin.get();
            if (existing.getGithubId() != null) {
                // GitHub logins can be renamed and re-registered: never move a record
                // that already belongs to another GitHub account.
                log.warn("Developer id={} with identifier '{}' is already linked to another GitHub account",
                        existing.getId(), login);
                throw new DuplicateResourceException(
                        "Developer identifier '" + login + "' is already linked to a different GitHub account");
            }
            Developer saved = developerRepository.save(refreshProfile(existing, githubId, profile));
            log.info("Linked githubId to legacy developer id={} (matched by verified login)", saved.getId());
            return DeveloperResponse.from(saved);
        }

        // ── Step 3: create a new Developer record ─────────────────────────────
        Developer newDeveloper = Developer.builder()
                .developerIdentifier(login)
                .githubId(githubId)
                .githubUsername(login)
                .email(profile.getEmail())
                .build();

        Developer saved = developerRepository.save(newDeveloper);
        log.info("Created new developer id={} for githubId={}", saved.getId(), githubId);
        return DeveloperResponse.from(saved);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Refresh GitHub profile fields on an existing Developer record from the verified profile.
     * The developerIdentifier and id are never overwritten. A private (null) email on GitHub
     * does not clear a previously stored one.
     */
    private Developer refreshProfile(Developer developer, String githubId, GitHubUserProfile profile) {
        developer.setGithubId(githubId);
        developer.setGithubUsername(profile.getLogin());
        if (profile.getEmail() != null && !profile.getEmail().isBlank()) {
            developer.setEmail(profile.getEmail());
        }
        return developer;
    }
}
