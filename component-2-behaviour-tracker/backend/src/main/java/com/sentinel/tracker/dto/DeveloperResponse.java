package com.sentinel.tracker.dto;

import com.sentinel.tracker.entity.Developer;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * Response DTO for Developer resources.
 * Exposes only safe, non-sensitive fields to API consumers.
 */
@Data
@Builder
public class DeveloperResponse {

    private Long id;
    private String developerIdentifier;
    private String githubId;
    private String githubUsername;
    private String email;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /**
     * Factory method: converts a Developer entity to a DeveloperResponse DTO.
     */
    public static DeveloperResponse from(Developer developer) {
        return DeveloperResponse.builder()
                .id(developer.getId())
                .developerIdentifier(developer.getDeveloperIdentifier())
                .githubId(developer.getGithubId())
                .githubUsername(developer.getGithubUsername())
                .email(developer.getEmail())
                .createdAt(developer.getCreatedAt())
                .updatedAt(developer.getUpdatedAt())
                .build();
    }
}
