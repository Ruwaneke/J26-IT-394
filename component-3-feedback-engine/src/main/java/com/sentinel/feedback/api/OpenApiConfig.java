package com.sentinel.feedback.api;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** OpenAPI document at /v3/api-docs; Swagger UI at /swagger-ui.html. */
@Configuration
public class OpenApiConfig {

    @Bean
    OpenAPI feedbackEngineApi() {
        return new OpenAPI().info(new Info()
                .title("Adaptive Security Coach - Component 3")
                .version("v1")
                .description("Rule-based, behaviour-aware feedback decisions and per-developer skill model."));
    }
}
