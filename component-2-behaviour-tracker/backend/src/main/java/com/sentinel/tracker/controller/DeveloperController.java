package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.CreateDeveloperRequest;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.service.DeveloperService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping("/api/developers")
@RequiredArgsConstructor
@Tag(name = "Developers", description = "Developer management endpoints")
public class DeveloperController {

    private final DeveloperService developerService;

    @PostMapping
    @Operation(summary = "Create a new developer")
    public ResponseEntity<DeveloperResponse> createDeveloper(
            @Valid @RequestBody CreateDeveloperRequest request) {

        DeveloperResponse response = developerService.createDeveloper(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a developer by ID")
    public ResponseEntity<DeveloperResponse> getDeveloperById(@PathVariable Long id) {
        return ResponseEntity.ok(developerService.getDeveloperById(id));
    }

    @GetMapping
    @Operation(summary = "Get all developers")
    public ResponseEntity<List<DeveloperResponse>> getAllDevelopers() {
        return ResponseEntity.ok(developerService.getAllDevelopers());
    }
}
