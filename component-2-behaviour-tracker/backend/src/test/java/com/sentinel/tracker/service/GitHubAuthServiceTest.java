package com.sentinel.tracker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.impl.GitHubAuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link GitHubAuthServiceImpl}.
 * Uses Mockito – no Spring context is loaded.
 */
@ExtendWith(MockitoExtension.class)
class GitHubAuthServiceTest {

    @Mock
    private DeveloperRepository developerRepository;

    @InjectMocks
    private GitHubAuthServiceImpl gitHubAuthService;

    private GitHubAuthRequest request;

    @BeforeEach
    void setUp() {
        request = new GitHubAuthRequest();
        request.setGithubId("1234567");
        request.setUsername("octocat");
        request.setEmail("octocat@github.com");
    }

    @Test
    @DisplayName("authenticateWithGitHub – should return existing developer matched by githubId")
    void authenticate_existingByGithubId_returnsExisting() {
        Developer existing = Developer.builder()
                .id(7L)
                .developerIdentifier("octocat")
                .githubId("1234567")
                .githubUsername("octocat")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.of(existing));
        when(developerRepository.save(any(Developer.class))).thenAnswer(inv -> inv.getArgument(0));

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);

        assertThat(response.getId()).isEqualTo(7L);
        assertThat(response.getEmail()).isEqualTo("octocat@github.com");
        verify(developerRepository, never()).findByDeveloperIdentifier(any());
    }

    @Test
    @DisplayName("authenticateWithGitHub – should link githubId to legacy developer matched by username")
    void authenticate_legacyByUsername_linksGithubId() {
        Developer legacy = Developer.builder()
                .id(3L)
                .developerIdentifier("octocat")
                .build();

        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.empty());
        when(developerRepository.findByDeveloperIdentifier("octocat")).thenReturn(Optional.of(legacy));
        when(developerRepository.save(any(Developer.class))).thenAnswer(inv -> inv.getArgument(0));

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);

        assertThat(response.getId()).isEqualTo(3L);
        assertThat(response.getGithubId()).isEqualTo("1234567");
        assertThat(response.getGithubUsername()).isEqualTo("octocat");
    }

    @Test
    @DisplayName("authenticateWithGitHub – should create a new developer when no match exists")
    void authenticate_newUser_createsDeveloper() {
        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.empty());
        when(developerRepository.findByDeveloperIdentifier("octocat")).thenReturn(Optional.empty());
        when(developerRepository.save(any(Developer.class))).thenAnswer(inv -> {
            Developer d = inv.getArgument(0);
            d.setId(42L);
            return d;
        });

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);

        ArgumentCaptor<Developer> captor = ArgumentCaptor.forClass(Developer.class);
        verify(developerRepository).save(captor.capture());
        Developer saved = captor.getValue();
        assertThat(saved.getDeveloperIdentifier()).isEqualTo("octocat");
        assertThat(saved.getGithubId()).isEqualTo("1234567");
        assertThat(saved.getGithubUsername()).isEqualTo("octocat");
        assertThat(saved.getEmail()).isEqualTo("octocat@github.com");
        assertThat(response.getId()).isEqualTo(42L);
    }

    @Test
    @DisplayName("GitHubAuthRequest – should accept githubUsername as an alias for username")
    void request_acceptsGithubUsernameAlias() throws Exception {
        String json = "{\"githubId\":\"1\",\"githubUsername\":\"octocat\",\"email\":\"o@x.com\"}";

        GitHubAuthRequest parsed = new ObjectMapper().readValue(json, GitHubAuthRequest.class);

        assertThat(parsed.getUsername()).isEqualTo("octocat");
    }
}
