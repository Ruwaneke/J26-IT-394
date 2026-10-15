package com.sentinel.tracker.service;

import com.sentinel.tracker.client.GitHubApiClient;
import com.sentinel.tracker.client.GitHubUserProfile;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.exception.DuplicateResourceException;
import com.sentinel.tracker.exception.GitHubApiException;
import com.sentinel.tracker.exception.InvalidGitHubTokenException;
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
 * Uses Mockito – no Spring context is loaded and no real GitHub calls are made.
 */
@ExtendWith(MockitoExtension.class)
class GitHubAuthServiceTest {

    private static final String TOKEN = "gho_validtoken";

    @Mock
    private DeveloperRepository developerRepository;

    @Mock
    private GitHubApiClient gitHubApiClient;

    @InjectMocks
    private GitHubAuthServiceImpl gitHubAuthService;

    private GitHubAuthRequest request;

    @BeforeEach
    void setUp() {
        request = new GitHubAuthRequest();
        request.setGithubAccessToken(TOKEN);
    }

    @Test
    @DisplayName("valid token – should create a new developer from the verified GitHub profile")
    void validToken_newUser_createsDeveloperFromVerifiedProfile() {
        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN))
                .thenReturn(new GitHubUserProfile(1234567L, "octocat", "octocat@github.com"));
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
    @DisplayName("valid token – should return existing developer matched by verified githubId")
    void validToken_existingByGithubId_returnsExisting() {
        Developer existing = Developer.builder()
                .id(7L)
                .developerIdentifier("octocat")
                .githubId("1234567")
                .githubUsername("old-login")
                .email("kept@example.com")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        // Private email on GitHub (null) must not clear the stored one
        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN))
                .thenReturn(new GitHubUserProfile(1234567L, "octocat", null));
        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.of(existing));
        when(developerRepository.save(any(Developer.class))).thenAnswer(inv -> inv.getArgument(0));

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);

        assertThat(response.getId()).isEqualTo(7L);
        assertThat(response.getGithubUsername()).isEqualTo("octocat");
        assertThat(response.getEmail()).isEqualTo("kept@example.com");
        assertThat(response.getDeveloperIdentifier()).isEqualTo("octocat");
        verify(developerRepository, never()).findByDeveloperIdentifier(any());
    }

    @Test
    @DisplayName("valid token – should link verified githubId to a legacy developer matched by verified login")
    void validToken_legacyByLogin_linksGithubId() {
        Developer legacy = Developer.builder()
                .id(3L)
                .developerIdentifier("octocat")
                .build();

        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN))
                .thenReturn(new GitHubUserProfile(1234567L, "octocat", "octocat@github.com"));
        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.empty());
        when(developerRepository.findByDeveloperIdentifier("octocat")).thenReturn(Optional.of(legacy));
        when(developerRepository.save(any(Developer.class))).thenAnswer(inv -> inv.getArgument(0));

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);

        assertThat(response.getId()).isEqualTo(3L);
        assertThat(response.getGithubId()).isEqualTo("1234567");
        assertThat(response.getGithubUsername()).isEqualTo("octocat");
        assertThat(response.getEmail()).isEqualTo("octocat@github.com");
    }

    @Test
    @DisplayName("valid token – should refuse to re-link a developer already owned by another GitHub account")
    void validToken_loginOwnedByOtherGithubAccount_throwsConflict() {
        Developer ownedByOther = Developer.builder()
                .id(5L)
                .developerIdentifier("octocat")
                .githubId("999")
                .build();

        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN))
                .thenReturn(new GitHubUserProfile(1234567L, "octocat", null));
        when(developerRepository.findByGithubId("1234567")).thenReturn(Optional.empty());
        when(developerRepository.findByDeveloperIdentifier("octocat")).thenReturn(Optional.of(ownedByOther));

        assertThatThrownBy(() -> gitHubAuthService.authenticateWithGitHub(request))
                .isInstanceOf(DuplicateResourceException.class);

        assertThat(ownedByOther.getGithubId()).isEqualTo("999");
        verify(developerRepository, never()).save(any());
    }

    @Test
    @DisplayName("invalid token – should throw and never touch the developer repository")
    void invalidToken_throwsAndDoesNotTouchRepository() {
        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN)).thenThrow(new InvalidGitHubTokenException());

        assertThatThrownBy(() -> gitHubAuthService.authenticateWithGitHub(request))
                .isInstanceOf(InvalidGitHubTokenException.class);

        verifyNoInteractions(developerRepository);
    }

    @Test
    @DisplayName("GitHub unavailable – should throw and never touch the developer repository")
    void gitHubUnavailable_throwsAndDoesNotTouchRepository() {
        when(gitHubApiClient.fetchAuthenticatedUser(TOKEN))
                .thenThrow(new GitHubApiException("Unable to verify GitHub token: GitHub API request failed"));

        assertThatThrownBy(() -> gitHubAuthService.authenticateWithGitHub(request))
                .isInstanceOf(GitHubApiException.class);

        verifyNoInteractions(developerRepository);
    }
}
