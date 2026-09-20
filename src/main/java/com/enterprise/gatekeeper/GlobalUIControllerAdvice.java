package com.enterprise.gatekeeper;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class GlobalUIControllerAdvice {
    @ModelAttribute("ssoLoginPath")
    public String getSsoLoginPath() {
        return SecurityConstants.LOGIN_ENDPOINT;
    }
}
