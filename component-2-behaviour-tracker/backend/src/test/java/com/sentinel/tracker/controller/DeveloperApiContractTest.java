package com.sentinel.tracker.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Contract tests for {@code /api/developers} on the real stack (TASKS P1-5).
 */
class DeveloperApiContractTest extends ApiContractTestSupport {

    private static final String PATH = "/api/developers";

    @Test
    void create_shouldReturn201WithResponseShape() throws Exception {
        postJson(PATH, "{\"developerIdentifier\":\"synthetic-dev-1\"}")
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.developerIdentifier").value("synthetic-dev-1"))
                .andExpect(jsonPath("$.githubId").doesNotExist())
                .andExpect(jsonPath("$.githubUsername").doesNotExist())
                .andExpect(jsonPath("$.email").doesNotExist())
                .andExpect(jsonPath("$.createdAt").isString())
                .andExpect(jsonPath("$.updatedAt").isString());
    }

    @Test
    void create_clientSuppliedGithubFields_shouldBeIgnored() throws Exception {
        // Only developerIdentifier is accepted; GitHub identity comes from GitHub at sign-in
        postJson(PATH, "{\"developerIdentifier\":\"synthetic-dev-2\",\"githubId\":\"1\","
                + "\"githubUsername\":\"octocat\",\"email\":\"someone@example.com\",\"id\":5}")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.githubId").doesNotExist())
                .andExpect(jsonPath("$.githubUsername").doesNotExist())
                .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void create_duplicateIdentifier_shouldReturn409AndKeepOneRow() throws Exception {
        postJson(PATH, "{\"developerIdentifier\":\"synthetic-dup\"}").andExpect(status().isCreated());

        postJson(PATH, "{\"developerIdentifier\":\"synthetic-dup\"}")
                .andExpect(status().isConflict())
                .andExpect(apiError(409, "Conflict", PATH))
                .andExpect(jsonPath("$.message").value("Developer already exists with identifier: synthetic-dup"));

        assertThat(developerRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"developerIdentifier\":null}", "{\"developerIdentifier\":\"\"}",
            "{\"developerIdentifier\":\"   \"}"})
    void create_missingOrBlankIdentifier_shouldReturn400(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH))
                .andExpect(jsonPath("$.message").value("developerIdentifier must not be blank"));
        assertThat(developerRepository.count()).isZero();
    }

    @Test
    void create_identifierLengthLimit_shouldBe255() throws Exception {
        postJson(PATH, "{\"developerIdentifier\":\"" + "d".repeat(256) + "\"}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("developerIdentifier must be at most 255 characters"));
        postJson(PATH, "{\"developerIdentifier\":\"" + "d".repeat(255) + "\"}")
                .andExpect(status().isCreated());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "nope", "[\"x\"]"})
    void create_malformedBody_shouldReturn400(String body) throws Exception {
        postJson(PATH, body)
                .andExpect(status().isBadRequest())
                .andExpect(apiError(400, "Bad Request", PATH));
    }

    @Test
    void getById_shouldReturn200() throws Exception {
        Long id = createDeveloper("synthetic-get");

        mockMvc.perform(get(PATH + "/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.developerIdentifier").value("synthetic-get"));
    }

    @Test
    void getById_unknown_shouldReturn404() throws Exception {
        mockMvc.perform(get(PATH + "/{id}", 123_456L))
                .andExpect(status().isNotFound())
                .andExpect(apiError(404, "Not Found", PATH + "/123456"))
                .andExpect(jsonPath("$.message").value("Developer not found with id: '123456'"));
    }

    @Test
    void getAll_shouldReturnEveryDeveloper() throws Exception {
        mockMvc.perform(get(PATH)).andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));

        createDeveloper("synthetic-a");
        createDeveloper("synthetic-b");

        mockMvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].developerIdentifier",
                        org.hamcrest.Matchers.containsInAnyOrder("synthetic-a", "synthetic-b")));
    }

    @Test
    void healthCheck_shouldReturnPlainText() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andExpect(content().string("Sentinel Behaviour Tracker Backend is Running"));
    }
}
