package com.sentinel.tracker.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * HTTP client configuration for the GitHub REST API.
 *
 * The base URL can be overridden with {@code github.api.base-url}
 * (e.g. for GitHub Enterprise or a local stub).
 */
@Configuration
public class GitHubClientConfig {

    private static final int TIMEOUT_MS = 5000;

    @Bean
    public RestClient gitHubRestClient(
            RestClient.Builder builder,
            @Value("${github.api.base-url:https://api.github.com}") String baseUrl) {

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(TIMEOUT_MS);
        requestFactory.setReadTimeout(TIMEOUT_MS);

        return builder
                .baseUrl(baseUrl)
                .requestFactory(requestFactory)
                .build();
    }
}
