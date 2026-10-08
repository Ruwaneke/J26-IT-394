package com.sentinel.tracker.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Verified identity returned by GitHub's {@code GET /user} endpoint.
 * Only the fields the backend uses are mapped.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class GitHubUserProfile {

    /** GitHub numeric user ID – stable for the lifetime of the account. */
    private Long id;

    /** GitHub login username (e.g. "octocat") – can be renamed by the user. */
    private String login;

    /** Public profile email; null when the user keeps their email private. */
    private String email;
}
