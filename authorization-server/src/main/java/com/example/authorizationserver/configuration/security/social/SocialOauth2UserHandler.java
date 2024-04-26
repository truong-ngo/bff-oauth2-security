package com.example.authorizationserver.configuration.security.social;

import com.example.authorizationserver.model.User;
import com.example.authorizationserver.service.core.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Consumer;

/**
 * Save social user ({@link OAuth2User}) when using social login
 * */
@Slf4j
@Component
@RequiredArgsConstructor
public class SocialOauth2UserHandler implements Consumer<OAuth2User> {

    @Value("${user.default_password}")
    private String defaultPassword;

    private final PasswordEncoder passwordEncoder;

    private final UserService userService;

    @Override
    public void accept(OAuth2User oAuth2User) {
        if (!this.userService.userExists(oAuth2User.getName())) {
            log.info(
                    "Saving first-time user: name = {}, claims = {}, authorities = {}",
                    oAuth2User.getName(),
                    oAuth2User.getAttributes(),
                    oAuth2User.getAuthorities());
            User user = new User(oAuth2User.getName(), passwordEncoder.encode(defaultPassword), List.of("ROLE_USER"));
            userService.createUser(user);
        }
    }
}
