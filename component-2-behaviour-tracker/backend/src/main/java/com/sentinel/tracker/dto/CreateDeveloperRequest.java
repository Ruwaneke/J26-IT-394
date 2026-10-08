package com.sentinel.tracker.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request DTO for creating a new Developer.
 */
@Data
public class CreateDeveloperRequest {

    @NotBlank(message = "developerIdentifier must not be blank")
    @Size(max = 255, message = "developerIdentifier must be at most 255 characters")
    private String developerIdentifier;
}
