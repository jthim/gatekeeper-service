package com.enterprise.gatekeeper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

@Component
public class RoleBasedSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(RoleBasedSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(authentication);

        if (response.isCommitted()) {
            return;
        }
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(Authentication authentication) {
        var roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        if (roles.contains("APPROLE_ROLE_ADMIN")) return "/dashboard/admin";
        if (roles.contains("APPROLE_ROLE_USER")) return "/dashboard";

        // Authenticated via Azure AD, but no recognized app role was assigned.
        // Likely a misconfigured app role assignment on the Azure side - log error.
        logger.warn("[SECURITY] Authenticated user '{}' has no recognized app role. Authorities: {}",
                authentication.getName(), roles);
        return "/error";
    }
}
