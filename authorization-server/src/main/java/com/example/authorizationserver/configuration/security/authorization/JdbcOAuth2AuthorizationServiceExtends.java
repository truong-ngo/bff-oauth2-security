package com.example.authorizationserver.configuration.security.authorization;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;

/**
 * Extension of {@link JdbcOAuth2AuthorizationService} for delete {@link OAuth2Authorization} by id token when logout
 * */
@Slf4j
@Service
@RequiredArgsConstructor
public class JdbcOAuth2AuthorizationServiceExtends {

    private final JdbcTemplate template;

    private static final String TABLE_NAME = "oauth2_authorization";

    private static final String ID_TOKEN_FILTER = "oidc_id_token_value = ?";

    public boolean deleteByIdToken(String idToken) {
        String deleteSql = "delete from " + TABLE_NAME + " where " + ID_TOKEN_FILTER;
        return template.update(deleteSql, idToken) != 0;
    }

}
