package com.sentinel.tracker.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Root health-check endpoint for the Sentinel Behaviour Tracker backend.
 */
@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "Sentinel Behaviour Tracker Backend is Running";
    }
}
