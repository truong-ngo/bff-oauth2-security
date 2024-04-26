package com.example.authorizationserver.configuration.security.authorization;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcLogoutEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Custom of {@link OidcLogoutEndpointFilter} that add delete {@link OAuth2Authorization} process when logout
 * */
public class CustomOidcLogoutEndpointFilter extends OncePerRequestFilter {
    private static final String DEFAULT_OIDC_LOGOUT_ENDPOINT_URI = "/connect/logout";

    private final AuthenticationManager authenticationManager;
    private final RequestMatcher logoutEndpointMatcher;
    private final LogoutHandler logoutHandler;
    private LogoutSuccessHandler logoutSuccessHandler;
    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler = this::performLogout;
    private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

    public CustomOidcLogoutEndpointFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, DEFAULT_OIDC_LOGOUT_ENDPOINT_URI);
    }

    public CustomOidcLogoutEndpointFilter(AuthenticationManager authenticationManager,
                                          String logoutEndpointUri) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.hasText(logoutEndpointUri, "logoutEndpointUri cannot be empty");
        this.authenticationManager = authenticationManager;
        this.logoutEndpointMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(logoutEndpointUri, HttpMethod.GET.name()),
                new AntPathRequestMatcher(logoutEndpointUri, HttpMethod.POST.name()));
        this.logoutHandler = new SecurityContextLogoutHandler();
        this.authenticationConverter = new OidcLogoutAuthenticationConverter();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.logoutEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication oidcLogoutAuthentication = this.authenticationConverter.convert(request);

            Authentication oidcLogoutAuthenticationResult =
                    this.authenticationManager.authenticate(oidcLogoutAuthentication);

            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, oidcLogoutAuthenticationResult);
        } catch (OAuth2AuthenticationException ex) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Logout request failed: %s", ex.getError()), ex);
            }
            this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        } catch (Exception ex) {
            OAuth2Error error = new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OpenID Connect 1.0 RP-Initiated Logout Error: " + ex.getMessage(),
                    "https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(error, ex);
            }
            this.authenticationFailureHandler.onAuthenticationFailure(request, response,
                    new OAuth2AuthenticationException(error));
        }
    }

    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public void setLogoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
        this.logoutSuccessHandler = logoutSuccessHandler;
    }

    private void performLogout(HttpServletRequest request, HttpServletResponse response,
                               Authentication authentication) throws IOException, ServletException {

        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

        // Check for active user session
        if (oidcLogoutAuthentication.isPrincipalAuthenticated() &&
                StringUtils.hasText(oidcLogoutAuthentication.getSessionId())) {
            // Perform logout
            this.logoutHandler.logout(request, response,
                    (Authentication) oidcLogoutAuthentication.getPrincipal());
        }

        this.logoutSuccessHandler.onLogoutSuccess(request, response, oidcLogoutAuthentication);
    }

    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationException exception) throws IOException {

        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
        response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
    }
}
