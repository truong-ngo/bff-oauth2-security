package com.example.authorizationserver.configuration.security;

import com.example.authorizationserver.configuration.security.authorization.JdbcOAuth2AuthorizationServiceExtends;
import com.example.authorizationserver.configuration.security.authorization.CustomOidcLogoutEndpointFilter;
import com.example.authorizationserver.configuration.security.authorization.LazyAuthenticationManager;
import com.example.authorizationserver.configuration.security.authorization.PostLogoutRedirectUriLogoutSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final ApplicationContext context;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .anonymous(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()))
                .addFilterAfter(customOidcLogoutEndpointFilter(http), CsrfFilter.class);
        return http.build();
    }

    public CustomOidcLogoutEndpointFilter customOidcLogoutEndpointFilter(HttpSecurity http) {
        CustomOidcLogoutEndpointFilter customOidcLogoutEndpointFilter = new CustomOidcLogoutEndpointFilter(new LazyAuthenticationManager(http));
        JdbcOAuth2AuthorizationServiceExtends oAuth2AuthorizationServiceExtends = context.getBean(JdbcOAuth2AuthorizationServiceExtends.class);
        customOidcLogoutEndpointFilter.setLogoutSuccessHandler(new PostLogoutRedirectUriLogoutSuccessHandler(oAuth2AuthorizationServiceExtends));
        return customOidcLogoutEndpointFilter;
    }
}
