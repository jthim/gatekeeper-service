package com.enterprise.gatekeeper.gatekeeper_service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@EnableMethodSecurity
public class IndexController {

    @GetMapping("/")
    public String showLandingPage(){
        return "index";
    }

    @GetMapping("/dashboard/admin")
    @PreAuthorize("hasAuthority('APPROLE_ROLE_ADMIN')")
    public String showAdminDashboard() {
        return "admin-dashboard";
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasAnyAuthority('APPROLE_ROLE_ADMIN','APPROLE_ROLE_USER')")
    public String showDashboard(@AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            System.out.println("=================== APPSEC AUDIT TRAIL ===================");
            System.out.println("VERIFIED USER EMAIL : " + principal.getEmail());
            System.out.println("IDENTITY ISSUER     : " + principal.getIssuer());
            System.out.println("TOKEN EXPIRES AT    : " + principal.getExpiresAt());
            System.out.println("CRYPTO CLAIMS BLOB  : " + principal.getClaims());
            System.out.println("==========================================================");
        }
        return "dashboard";
    }
}
