package com.sentinel.tracker.controller;

import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.dto.GitHubAuthRequest;
import com.sentinel.tracker.service.GitHubAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for GitHub identity integration.
 *
 * Receives an authenticated GitHub user's profile from the VS Code extension
 * and maps it to an existing or newly created Developer record.
 *
 * Base path: /api/auth
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "GitHub Auth", description = "GitHub identity integration endpoints")
public class GitHubAuthController {

    private final GitHubAuthService gitHubAuthService;

    /**
     * POST /api/auth/github
     *
     * <p>Called by the VS Code extension immediately after GitHub OAuth completes.
     * Returns the Developer profile (existing or newly created) that corresponds
     * to the authenticated GitHub user.</p>
     *
     * <p>Response codes:</p>
     * <ul>
     *   <li>200 OK – developer found and returned (existing record)</li>
     *   <li>200 OK – developer created and returned (new record)</li>
     *   <li>400 Bad Request – validation failure on request body</li>
     * </ul>
     */
    @PostMapping("/github")
    @Operation(
        summary = "Authenticate via GitHub",
        description = "Maps an authenticated GitHub user to an existing or new Developer record. "
                    + "Returns 200 in both the found and created cases."
    )
    public ResponseEntity<DeveloperResponse> authenticateWithGitHub(
            @Valid @RequestBody GitHubAuthRequest request) {

        DeveloperResponse response = gitHubAuthService.authenticateWithGitHub(request);
        return ResponseEntity.ok(response);
    }
}
