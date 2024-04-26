package com.example.authorizationserver.configuration.security.authorization;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class LazyAuthenticationManager implements AuthenticationManager {
    private final HttpSecurity http;

    private AuthenticationManager manager;

    public LazyAuthenticationManager(HttpSecurity http) {
        this.http = http;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return getAuthenticationManager().authenticate(authentication);
    }

    private AuthenticationManager getAuthenticationManager() {
        if (this.manager == null) {
            this.manager = this.http.getSharedObject(AuthenticationManager.class);
        }
        return this.manager;
    }
}
