package com.sentinel.tracker.client;

import com.sentinel.tracker.exception.GitHubApiException;
import com.sentinel.tracker.exception.InvalidGitHubTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Thin client for the GitHub REST API, used to verify access tokens sent by
 * the VS Code extension.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class GitHubApiClient {

    private static final MediaType GITHUB_JSON = MediaType.parseMediaType("application/vnd.github+json");

    private final RestClient gitHubRestClient;

    /**
     * Calls {@code GET /user} with the given token and returns the verified profile.
     *
     * @throws InvalidGitHubTokenException if GitHub rejects the token (401)
     * @throws GitHubApiException          if GitHub is unreachable, errors, or returns an unusable profile
     */
    public GitHubUserProfile fetchAuthenticatedUser(String accessToken) {
        GitHubUserProfile profile;
        try {
            profile = gitHubRestClient.get()
                    .uri("/user")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .accept(GITHUB_JSON)
                    .retrieve()
                    .body(GitHubUserProfile.class);
        } catch (HttpClientErrorException.Unauthorized ex) {
            log.warn("GitHub rejected the supplied access token");
            throw new InvalidGitHubTokenException();
        } catch (RestClientException ex) {
            log.error("GitHub token verification failed: {}", ex.getMessage());
            throw new GitHubApiException("Unable to verify GitHub token: GitHub API request failed", ex);
        }

        if (profile == null || profile.getId() == null
                || profile.getLogin() == null || profile.getLogin().isBlank()) {
            throw new GitHubApiException("Unable to verify GitHub token: GitHub returned an incomplete user profile");
        }
        return profile;
    }
}
