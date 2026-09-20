package com.enterprise.gatekeeper.gatekeeper_service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository, RoleBasedSuccessHandler roleBasedSuccessHandler, RateLimitingFilter rateLimitingFilter) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter, SecurityContextHolderFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // Allow the general public to view root landing page
                        .requestMatchers("/", "/error").permitAll()
                        // Keep all other future endpoints securely locked down
                        .anyRequest().authenticated()
                )
                // Enable official Microsoft Entra ID OIDC login
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(customAuthorizationRequestResolver(clientRegistrationRepository))
                        )
                        .successHandler(roleBasedSuccessHandler)
                        // 2. Override default Oauth error page to custom one, and log the failure
                        // so failed-login attempts show up in the audit trail.
                        .failureHandler((request, response, exception) -> {
                            logger.warn("[SECURITY] OAuth2 login failed from IP {}: {}",
                                    request.getRemoteAddr(), exception.getMessage());
                            request.getRequestDispatcher("/error").forward(request, response);
                        })
                )
                // Log and hand off any 403 (authenticated, but not permitted) to /error too,
                // e.g. a USER-role account trying to reach /dashboard/admin directly.
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedHandler((request, response, exception) -> {
                            var principal = request.getUserPrincipal();
                            logger.warn("[SECURITY] Access denied for user '{}' to {} from IP {}",
                                    principal != null ? principal.getName() : "unknown",
                                    request.getRequestURI(), request.getRemoteAddr());
                            request.getRequestDispatcher("/error").forward(request, response);
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

    // Custom request resolver
    private OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization"
                );

        // Add param to have Microsoft prompt user to select account
        resolver.setAuthorizationRequestCustomizer(customizer ->
                customizer.additionalParameters(params -> params.put("prompt", "select_account"))
        );

        return resolver;

    }
}