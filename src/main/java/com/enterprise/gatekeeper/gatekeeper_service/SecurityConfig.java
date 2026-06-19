package com.enterprise.gatekeeper.gatekeeper_service;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RoleBasedSuccessHandler roleBasedSuccessHandler;

    // Use my custom success handler via Dependency Injection
    public SecurityConfig(RoleBasedSuccessHandler roleBasedSuccessHandler) {
        this.roleBasedSuccessHandler = roleBasedSuccessHandler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // Allow the general public to view root landing page
                        .requestMatchers("/").permitAll()
                        // Keep all other future endpoints securely locked down
                        .anyRequest().authenticated()
                )
                // Enable official Microsoft Entra ID OIDC login
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(config -> config
                                .baseUri(SecurityConstants.SSO_BASE_URI)
                        )
                        .successHandler(roleBasedSuccessHandler)
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                );

        return http.build();
    }
}