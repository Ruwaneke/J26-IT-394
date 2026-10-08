package com.sentinel.tracker.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.ToString;

/**
 * Request payload for the GitHub authentication endpoint.
 *
 * Sent by the VS Code extension after it has completed GitHub OAuth.
 * Only the access token is accepted: the backend verifies it with GitHub and
 * derives the developer's identity (id, login, email) from GitHub's response.
 * Any other fields in the JSON body (e.g. githubId, githubUsername, email) are ignored.
 */
@Data
public class GitHubAuthRequest {

    /**
     * OAuth access token from the VS Code GitHub authentication session.
     * Never logged.
     */
    @NotBlank(message = "githubAccessToken must not be blank")
    @Size(max = 500, message = "githubAccessToken must be at most 500 characters")
    @ToString.Exclude
    private String githubAccessToken;
}
