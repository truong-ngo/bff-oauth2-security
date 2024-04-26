package com.example.authorizationserver.configuration.security.authorization;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Handler delete {@link OAuth2Authorization} and redirect when logout success
 * */
@Slf4j
@RequiredArgsConstructor
public class PostLogoutRedirectUriLogoutSuccessHandler implements LogoutSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final JdbcOAuth2AuthorizationServiceExtends oAuth2AuthorizationServiceExtends;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OidcLogoutAuthenticationToken oidcLogoutAuthentication)) {
            return;
        }

        if (oidcLogoutAuthentication.isAuthenticated() &&
                StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {

            // Delete oauth2 authorization from database
            log.info("Delete oauth2 authorization record of session: {}", oidcLogoutAuthentication.getSessionId());

            if (oAuth2AuthorizationServiceExtends.deleteByIdToken(Objects.requireNonNull(oidcLogoutAuthentication.getIdToken()).getTokenValue())) {
                log.info("OAuth2 authorization deleted successfully");
            } else {
                log.info("OAuth2 authorization not found");
            }

            // Perform post-logout redirect
            UriComponentsBuilder uriBuilder = UriComponentsBuilder
                    .fromUriString(oidcLogoutAuthentication.getPostLogoutRedirectUri());
            String redirectUri;
            if (StringUtils.hasText(oidcLogoutAuthentication.getState())) {
                uriBuilder.queryParam(
                        OAuth2ParameterNames.STATE,
                        UriUtils.encode(oidcLogoutAuthentication.getState(), StandardCharsets.UTF_8));
            }
            redirectUri = uriBuilder.build(true).toUriString();		// build(true) -> Components are explicitly encoded
            this.redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            // Perform default redirect
            this.redirectStrategy.sendRedirect(request, response, "/");
        }
    }
}
