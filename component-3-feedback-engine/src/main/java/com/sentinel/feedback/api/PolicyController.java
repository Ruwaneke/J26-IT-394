package com.sentinel.feedback.api;

import com.sentinel.feedback.policy.PolicyProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/policy")
public class PolicyController {

    private final PolicyProperties policy;

    public PolicyController(PolicyProperties policy) {
        this.policy = policy;
    }

    /** The active decision policy: weights, level thresholds, mastery parameters, overrides. */
    @GetMapping
    public PolicyProperties activePolicy() {
        return policy;
    }
}
