package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.dto.DeveloperResponse;

/**
 * Service contract for GitHub identity integration.
 *
 * Responsible for mapping an authenticated GitHub user to an existing or
 * newly created Developer record. All existing Developer, BehaviourLog,
 * SecurityEvent, and BehaviourAnalysis logic is untouched.
 */
public interface GitHubAuthService {

    /**
     * Find-or-create a Developer record for the authenticated GitHub user.
     *
     * <ul>
     *   <li>If a Developer with the given {@code githubId} already exists,
     *       it is returned immediately (its profile fields are refreshed).</li>
     *   <li>If no match is found, a new Developer is created using the
     *       GitHub username as the {@code developerIdentifier}.</li>
     * </ul>
     *
     * @param request validated payload from the VS Code extension
     * @return the existing or newly created Developer as a response DTO
     */
    DeveloperResponse authenticateWithGitHub(GitHubAuthRequest request);
}
