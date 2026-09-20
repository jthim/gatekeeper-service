package com.enterprise.gatekeeper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
class RateLimitingFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Should allow requests under threshold but return 429 when limit exceeded")
    void enforceRateLimitPolicy() throws Exception {
        String testIp = "192.168.1.50";

        // 1. Simulate a user hitting the landing page 20 times (within the allowed threshold)
        // Since "/" allows permitAll(), it should return 200 OK
        for (int i = 0; i < 20; i++) {
            mockMvc.perform(get("/")
                            .with(request -> {
                                request.setRemoteAddr(testIp); // Force a specific client IP
                                return request;
                            }))
                    .andExpect(status().isOk());
        }

        // 2. The 21st sequential request must be violently dropped by Bucket4j
        mockMvc.perform(get("/")
                        .with(request -> {
                            request.setRemoteAddr(testIp);
                            return request;
                        }))
                .andExpect(status().is(429)); // Verifies the HTTP 429 perimeter defense
    }
}