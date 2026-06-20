package com.enterprise.gatekeeper.gatekeeper_service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

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
                        .requestMatchers("/", "/error").permitAll()
                        // Keep all other future endpoints securely locked down
                        .anyRequest().authenticated()
                )
                // Enable official Microsoft Entra ID OIDC login
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(config -> config
                                .baseUri(SecurityConstants.SSO_BASE_URI)
                        )
                        .successHandler(roleBasedSuccessHandler)
                        // 2. OVERRIDE DEFAULT OAUTH FAILURE PAGE TO CUSTOM
                        .failureHandler(new AuthenticationFailureHandler() {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                request.getRequestDispatcher("/error").forward(request, response);
                            }
                        })
                )
                .logout(logout -> logout
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/")
                );

        return http.build();
    }
}