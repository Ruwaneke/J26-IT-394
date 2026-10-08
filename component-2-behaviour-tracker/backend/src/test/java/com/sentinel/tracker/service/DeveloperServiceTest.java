package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperRequest;
import com.sentinel.tracker.dto.DeveloperResponse;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.exception.DuplicateResourceException;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.impl.DeveloperServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link DeveloperServiceImpl}.
 * Uses Mockito – no Spring context is loaded.
 */
@ExtendWith(MockitoExtension.class)
class DeveloperServiceTest {

    @Mock
    private DeveloperRepository developerRepository;

    @InjectMocks
    private DeveloperServiceImpl developerService;

    private Developer sampleDeveloper;

    @BeforeEach
    void setUp() {
        sampleDeveloper = Developer.builder()
                .id(1L)
                .developerIdentifier("dev-001")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    // ── createDeveloper ───────────────────────────────────────────────────────

    @Test
    @DisplayName("createDeveloper – should create and return developer successfully")
    void createDeveloper_shouldCreateSuccessfully() {
        // Arrange
        CreateDeveloperRequest request = new CreateDeveloperRequest();
        request.setDeveloperIdentifier("dev-001");

        when(developerRepository.existsByDeveloperIdentifier("dev-001")).thenReturn(false);
        when(developerRepository.save(any(Developer.class))).thenReturn(sampleDeveloper);

        // Act
        DeveloperResponse response = developerService.createDeveloper(request);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getDeveloperIdentifier()).isEqualTo("dev-001");
        verify(developerRepository, times(1)).save(any(Developer.class));
    }

    @Test
    @DisplayName("createDeveloper – should throw DuplicateResourceException when identifier already exists")
    void createDeveloper_shouldThrowWhenDuplicate() {
        // Arrange
        CreateDeveloperRequest request = new CreateDeveloperRequest();
        request.setDeveloperIdentifier("dev-001");

        when(developerRepository.existsByDeveloperIdentifier("dev-001")).thenReturn(true);

        // Act & Assert
        assertThatThrownBy(() -> developerService.createDeveloper(request))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("dev-001");

        verify(developerRepository, never()).save(any());
    }

    // ── getDeveloperById ──────────────────────────────────────────────────────

    @Test
    @DisplayName("getDeveloperById – should return developer when found")
    void getDeveloperById_shouldReturnWhenFound() {
        when(developerRepository.findById(1L)).thenReturn(Optional.of(sampleDeveloper));

        DeveloperResponse response = developerService.getDeveloperById(1L);

        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getDeveloperIdentifier()).isEqualTo("dev-001");
    }

    @Test
    @DisplayName("getDeveloperById – should throw ResourceNotFoundException when not found")
    void getDeveloperById_shouldThrowWhenNotFound() {
        when(developerRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> developerService.getDeveloperById(999L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("999");
    }

    // ── getAllDevelopers ──────────────────────────────────────────────────────

    @Test
    @DisplayName("getAllDevelopers – should return list of all developers")
    void getAllDevelopers_shouldReturnAll() {
        when(developerRepository.findAll()).thenReturn(List.of(sampleDeveloper));

        List<DeveloperResponse> responses = developerService.getAllDevelopers();

        assertThat(responses).hasSize(1);
        assertThat(responses.get(0).getDeveloperIdentifier()).isEqualTo("dev-001");
    }
}
