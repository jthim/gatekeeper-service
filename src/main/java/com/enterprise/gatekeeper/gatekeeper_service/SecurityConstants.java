package com.enterprise.gatekeeper.gatekeeper_service;

public final class SecurityConstants {
    public static final String SSO_BASE_URI = "/login/sso";
    public static final String AZURE_REGISTRATION_ID = "azure";

    public static final String LOGIN_ENDPOINT = SSO_BASE_URI + "/" + AZURE_REGISTRATION_ID;
}