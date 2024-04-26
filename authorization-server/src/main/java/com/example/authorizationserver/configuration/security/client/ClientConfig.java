package com.example.authorizationserver.configuration.security.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientConfig {

    private final PasswordEncoder passwordEncoder;

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {

        RegisteredClientRepository repository = new JdbcRegisteredClientRepository(template);
        RegisteredClient webBFFClient = repository.findByClientId("web-application");

        if (webBFFClient == null) {
            webBFFClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("web-application")
                    .clientSecret(passwordEncoder.encode("web-app-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
                    .postLogoutRedirectUri("http://127.0.0.1:8082")
                    .scope(OidcScopes.OPENID)
                    .scope("user.read")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();
            repository.save(webBFFClient);
        }

        return repository;
    }
}
