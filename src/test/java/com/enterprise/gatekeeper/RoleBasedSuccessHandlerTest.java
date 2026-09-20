package com.enterprise.gatekeeper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.RedirectStrategy;

import java.util.List;

import static org.mockito.Mockito.*;

class RoleBasedSuccessHandlerTest {

    private RoleBasedSuccessHandler successHandler;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private Authentication authentication;
    private RedirectStrategy redirectStrategy;

    @BeforeEach
    void setUp() {
        successHandler = new RoleBasedSuccessHandler();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        authentication = mock(Authentication.class);
        redirectStrategy = mock(RedirectStrategy.class);

        // Inject the mocked redirect strategy into the handler
        successHandler.setRedirectStrategy(redirectStrategy);
    }

    @Test
    @DisplayName("Should redirect to admin dashboard when user has ADMIN role")
    void redirectAdminUser() throws Exception {
        var adminAuthority = new SimpleGrantedAuthority("APPROLE_ROLE_ADMIN");
        doReturn(List.of(adminAuthority)).when(authentication).getAuthorities();
        when(response.isCommitted()).thenReturn(false);

        successHandler.onAuthenticationSuccess(request, response, authentication);

        verify(redirectStrategy).sendRedirect(request, response, "/dashboard/admin");
    }

    @Test
    @DisplayName("Should redirect to standard dashboard when user has USER role")
    void redirectStandardUser() throws Exception {
        var userAuthority = new SimpleGrantedAuthority("APPROLE_ROLE_USER");
        doReturn(List.of(userAuthority)).when(authentication).getAuthorities();
        when(response.isCommitted()).thenReturn(false);

        successHandler.onAuthenticationSuccess(request, response, authentication);

        verify(redirectStrategy).sendRedirect(request, response, "/dashboard");
    }

    @Test
    @DisplayName("Should redirect to the error page when role is not recognized")
    void handleUnmappedRole() throws Exception {
        var unknownAuthority = new SimpleGrantedAuthority("APPROLE_ROLE_INVALID");
        doReturn(List.of(unknownAuthority)).when(authentication).getAuthorities();
        when(response.isCommitted()).thenReturn(false);

        successHandler.onAuthenticationSuccess(request, response, authentication);

        verify(redirectStrategy).sendRedirect(request, response, "/error");
    }

}