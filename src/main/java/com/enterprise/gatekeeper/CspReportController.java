package com.enterprise.gatekeeper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives Content-Security-Policy violation reports.
 * This endpoint is  unauthenticated on purpose because the browser sends this report on its own,
 * with no user session involved - it isn't a user action, so there's no login/CSRF context to check it against.
 */
@RestController
public class CspReportController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportController.class);

    @PostMapping(value = "/csp-violation-report", consumes = {"application/csp-report", "application/json"})
    public void reportViolation(@RequestBody String violationReport) {
        // Logged at the same [SECURITY] level as auth failures and access-denied
        // events, so it shows up alongside them in the same audit trail.
        logger.warn("[SECURITY] CSP violation reported: {}", violationReport);
    }
}
 