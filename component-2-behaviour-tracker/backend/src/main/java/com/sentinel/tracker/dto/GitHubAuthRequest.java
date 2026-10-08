package com.sentinel.tracker.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request payload for the GitHub authentication endpoint.
 *
 * Sent by the VS Code extension after it has completed GitHub OAuth and
 * obtained the user's profile information.
 */
@Data
public class GitHubAuthRequest {

    /**
     * GitHub's numeric user ID (e.g. "1234567").
     * Used as the primary lookup key to identify an existing developer.
     */
    @NotBlank(message = "githubId must not be blank")
    @Size(max = 100, message = "githubId must be at most 100 characters")
    private String githubId;

    /**
     * GitHub login username (e.g. "octocat").
     * Stored as the developerIdentifier for new accounts and kept in sync.
     * Accepts either "username" or "githubUsername" in the JSON body.
     */
    @JsonAlias("githubUsername")
    @NotBlank(message = "username must not be blank")
    @Size(max = 255, message = "username must be at most 255 characters")
    private String username;

    /**
     * Primary email address from the GitHub profile.
     * Optional – GitHub accounts without a public email may omit this.
     */
    @Size(max = 255, message = "email must be at most 255 characters")
    private String email;
}
