package com.enterprise.gatekeeper;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@EnableMethodSecurity
public class IndexController {

    @GetMapping("/")
    public String showLandingPage() {
        return "index";
    }

    @GetMapping("/dashboard/admin")
    @PreAuthorize("hasAuthority('APPROLE_ROLE_ADMIN')")
    public String showAdminDashboard(@AuthenticationPrincipal OidcUser principal, Model model) {
        getUserInfo(principal, model);
        return "admin-dashboard";
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasAnyAuthority('APPROLE_ROLE_ADMIN','APPROLE_ROLE_USER')")
    public String showDashboard(@AuthenticationPrincipal OidcUser principal, Model model) {
        getUserInfo(principal, model);
        return "dashboard";
    }

    private void getUserInfo(OidcUser principal, Model model) {
        model.addAttribute("userFullName", principal.getFullName());
    }
}
