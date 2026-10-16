package com.sentinel.feedback.recommendation;

import com.sentinel.feedback.model.VulnerabilityType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecommendationTemplateServiceTest {

    private final RecommendationTemplateService service = new RecommendationTemplateService();

    @Test
    void providesTemplatesForAllCoreVulnerabilityCategories() {
        for (VulnerabilityType type : VulnerabilityType.values()) {
            RecommendationTemplate template = service.getTemplate(type);

            assertFalse(template.title().isBlank());
            assertFalse(template.guidance().isBlank());
            assertFalse(template.secureExample().isBlank());
        }
    }

    @Test
    void providesCategorySpecificSecureGuidance() {
        RecommendationTemplate sql = service.getTemplate(VulnerabilityType.SQL_INJECTION);
        RecommendationTemplate xss = service.getTemplate(VulnerabilityType.XSS);

        assertTrue(sql.guidance().contains("parameter"));
        assertTrue(xss.guidance().contains("Encode"));
        assertTrue(sql.secureExample().contains("PreparedStatement"));
        assertTrue(xss.secureExample().contains("textContent"));
    }
}
