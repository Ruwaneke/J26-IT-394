package com.sentinel.tracker.controller;

import com.sentinel.tracker.entity.Developer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseActions;
import org.springframework.web.client.RestClient;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract tests for {@code POST /api/auth/github} through the real controller, service,
 * {@code GitHubApiClient} and H2 (TASKS P1-5). Frozen C1 endpoint (TECHNICAL_OVERVIEW §0 rule 1).
 *
 * <p>GitHub is never called: {@code GET /user} is answered by a {@link MockRestServiceServer}
 * bound to the client's {@link RestClient}. The token is a made-up string.
 */
@ExtendWith(OutputCaptureExtension.class)
class GitHubAuthApiContractTest extends ApiContractTestSupport {

    private static final String PATH = "/api/auth/github";
    private static final String GITHUB = "https://github.test";
    private static final String TOKEN = "gho_SYNTHETIC_test_token_not_real_123";
    private static final String C1_BODY = "{\"githubAccessToken\":\"" + TOKEN + "\"}";

    @TestConfiguration
    static class MockGitHubConfig {

        private final RestClient.Builder builder = RestClient.builder().baseUrl(GITHUB);
        private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();

        @Bean
        MockRestServiceServer gitHubServer() {
            return server;
        }

        /** Replaces the real GitHub client (GitHubClientConfig) in this test context. */
        @Bean
        @Primary
        RestClient mockedGitHubRestClient() {
            return builder.build();
        }
    }

    @Autowired
    private MockRestServiceServer gitHub;

    @BeforeEach
    void resetGitHub() {
        gitHub.reset();
    }

    @AfterEach
    void verifyGitHubCalls() {
        gitHub.verify();
    }

    // ── Success ───────────────────────────────────────────────────────────────

    @Test
    void newGitHubUser_shouldReturn200AndCreateDeveloperFromTheVerifiedProfile() throws Exception {
        expectUserRequest().andRespond(profile(583231, "octo-synthetic", "octo@example.test"));

        postJson(PATH, C1_BODY)
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                // The fields C1 reads (sentinel/src/auth/authManager.ts BackendDeveloper)
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.developerIdentifier").value("octo-synthetic"))
                .andExpect(jsonPath("$.githubUsername").value("octo-synthetic"))
                .andExpect(jsonPath("$.email").value("octo@example.test"))
                .andExpect(jsonPath("$.githubId").value("583231"));

        Developer stored = developerRepository.findByGithubId("583231").orElseThrow();
        assertThat(stored.getDeveloperIdentifier()).isEqualTo("octo-synthetic");
    }

    @Test
    void returningGitHubUser_shouldReturnTheSameDeveloperAndRefreshTheLogin() throws Exception {
        Long id = developerRepository.save(Developer.builder().developerIdentifier("old-login")
                .githubId("583231").githubUsername("old-login").email("kept@example.test").build()).getId();
        // Renamed on GitHub, email now private
        expectUserRequest().andRespond(profile(583231, "new-login", null));

        postJson(PATH, C1_BODY)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.developerIdentifier").value("old-login"))
                .andExpect(jsonPath("$.githubUsername").value("new-login"))
                .andExpect(jsonPath("$.email").value("kept@example.test"));

        assertThat(developerRepository.count()).isEqualTo(1);
    }

    @Test
    void legacyDeveloperWithTheSameLogin_shouldBeLinked() throws Exception {
        Long id = createDeveloper("legacy-login");
        expectUserRequest().andRespond(profile(777, "legacy-login", null));

        postJson(PATH, C1_BODY)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.githubId").value("777"));

        assertThat(developerRepository.findById(id).orElseThrow().getGithubId()).isEqualTo("777");
        assertThat(developerRepository.count()).isEqualTo(1);
    }

    @Test
    void clientSuppliedIdentityFields_shouldBeIgnored() throws Exception {
        Long victimId = developerRepository.save(Developer.builder().developerIdentifier("victim")
                .githubId("1").githubUsername("victim").build()).getId();
        expectUserRequest().andRespond(profile(2, "attacker", null));

        // Identity claims in the body must not select or change any developer
        postJson(PATH, "{\"githubAccessToken\":\"" + TOKEN + "\",\"githubId\":\"1\",\"githubUsername\":\"victim\","
                + "\"developerIdentifier\":\"victim\",\"id\":" + victimId + ",\"email\":\"x@example.test\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(not(victimId.intValue())))
                .andExpect(jsonPath("$.developerIdentifier").value("attacker"))
                .andExpect(jsonPath("$.githubId").value("2"))
                .andExpect(jsonPath("$.email").doesNotExist());

        Developer victim = developerRepository.findById(victimId).orElseThrow();
        assertThat(victim.getGithubId()).isEqualTo("1");
        assertThat(victim.getEmail()).isNull();
    }

    // ── Conflict ──────────────────────────────────────────────────────────────

    @Test
    void loginLinkedToAnotherGitHubAccount_shouldReturn409AndChangeNothing() throws Exception {
        developerRepository.save(Developer.builder().developerIdentifier("taken-login")
                .githubId("100").githubUsername("taken-login").build());
        expectUserRequest().andRespond(profile(200, "taken-login", null));

        postJson(PATH, C1_BODY)
                .andExpect(status().isConflict())
                .andExpect(apiError(409, "Conflict", PATH))
                .andExpect(jsonPath("$.message").value(
                        "Developer identifier 'taken-login' is already linked to a different GitHub account"));

        assertThat(developerRepository.count()).isEqualTo(1);
        assertThat(developerRepository.findByGithubId("200")).isEmpty();
    }

    // ── GitHub failures ───────────────────────────────────────────────────────

    @Test
    void gitHubRejectsTheToken_shouldReturn401AndStoreNothing() throws Exception {
        expectUserRequest().andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"Bad credentials\"}"));

        postJson(PATH, C1_BODY)
                .andExpect(status().isUnauthorized())
                .andExpect(apiError(401, "Unauthorized", PATH))
                .andExpect(jsonPath("$.message").value("Invalid or expired GitHub access token"));

        assertThat(developerRepository.count()).isZero();
    }

    @Test
    void gitHubServerError_shouldReturn502() throws Exception {
        expectUserRequest().andRespond(withServerError());
        expectBadGateway("GitHub API request failed");
    }

    @Test
    void gitHubRateLimit_shouldReturn502() throws Exception {
        expectUserRequest().andRespond(withStatus(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON).body("{\"message\":\"API rate limit exceeded\"}"));
        expectBadGateway("GitHub API request failed");
    }

    @Test
    void gitHubUnreachable_shouldReturn502() throws Exception {
        expectUserRequest().andRespond(withException(new IOException("Connection refused")));
        expectBadGateway("GitHub API request failed");
    }

    @Test
    void gitHubReturnsANonJsonBody_shouldReturn502() throws Exception {
        expectUserRequest().andRespond(withSuccess("<html>maintenance</html>", MediaType.TEXT_HTML));
        expectBadGateway("GitHub API request failed");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"login\":\"no-id\"}", "{\"id\":5}", "{\"id\":5,\"login\":\"  \"}", "{}"})
    void gitHubReturnsAnIncompleteProfile_shouldReturn502(String body) throws Exception {
        expectUserRequest().andRespond(withSuccess(body, MediaType.APPLICATION_JSON));
        expectBadGateway("incomplete user profile");
    }

    // ── Validation (GitHub is not called) ─────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"githubAccessToken\":null}", "{\"githubAccessToken\":\"\"}",
            "{\"githubAccessToken\":\"   \"}"})
    void missingOrBlankToken_shouldReturn400WithoutCallingGitHub(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message").value("githubAccessToken must not be blank"));
    }

    @Test
    void tokenOver500Characters_shouldReturn400WithoutCallingGitHub() throws Exception {
        postJson(PATH, "{\"githubAccessToken\":\"" + "t".repeat(501) + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("githubAccessToken must be at most 500 characters"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "token", "[\"" + TOKEN + "\"]"})
    void malformedBody_shouldReturn400WithoutCallingGitHub(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH));
    }

    // ── Token handling ────────────────────────────────────────────────────────

    @Test
    void token_shouldNeverBeEchoedOrLogged(CapturedOutput output) throws Exception {
        expectUserRequest().andRespond(profile(9, "log-check", null));
        postJson(PATH, C1_BODY)
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString(TOKEN))));

        gitHub.reset();
        expectUserRequest().andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        postJson(PATH, C1_BODY)
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(not(containsString(TOKEN))));

        gitHub.reset();
        expectUserRequest().andRespond(withException(new IOException("Connection reset")));
        postJson(PATH, C1_BODY)
                .andExpect(status().isBadGateway())
                .andExpect(content().string(not(containsString(TOKEN))));

        assertThat(output.getAll()).doesNotContain(TOKEN);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Expects exactly the request {@code GitHubApiClient} sends to {@code GET /user}. */
    private ResponseActions expectUserRequest() {
        return gitHub.expect(requestTo(GITHUB + "/user"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer " + TOKEN))
                .andExpect(header("X-GitHub-Api-Version", "2022-11-28"));
    }

    private static org.springframework.test.web.client.ResponseCreator profile(long id, String login, String email) {
        return withSuccess("{\"id\":" + id + ",\"login\":\"" + login + "\",\"email\":"
                + (email == null ? "null" : "\"" + email + "\"") + ",\"name\":\"ignored\"}", MediaType.APPLICATION_JSON);
    }

    private void expectBadGateway(String messageFragment) throws Exception {
        postJson(PATH, C1_BODY)
                .andExpect(status().isBadGateway())
                .andExpect(apiError(502, "Bad Gateway", PATH))
                .andExpect(jsonPath("$.message", containsString(messageFragment)));
        assertThat(developerRepository.count()).isZero();
    }
}
