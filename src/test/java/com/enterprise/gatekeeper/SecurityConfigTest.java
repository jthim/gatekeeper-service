package com.enterprise.gatekeeper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Public Endpoints: Should allow anyone to access the root landing page")
    void publicEndpointsAccessible() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Public Endpoints: Should allow anyone to access the error route")
    void errorEndpointAccessible() throws Exception {
        mockMvc.perform(get("/error"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Protected Endpoints: Unauthenticated users should be redirected to the OAuth login challenge")
    void secureEndpointsRedirectToLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
                // Expect a 302 Redirect to the Spring Boot internal local OAuth start path
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .redirectedUrl("/oauth2/authorization/azure"));
    }

    @Test
    @DisplayName("Authenticated Endpoints: Users with matching OIDC authorities should bypass the login wall")
    void authenticatedOidcUserAccess() throws Exception {
        mockMvc.perform(get("/dashboard")
                        .with(oidcLogin()
                                .idToken(token -> token.claim("sub", "microsoft-user-123"))
                                .authorities(new org.springframework.security.core.authority.SimpleGrantedAuthority("APPROLE_ROLE_USER"))))
                .andExpect(status().isOk());
    }
}