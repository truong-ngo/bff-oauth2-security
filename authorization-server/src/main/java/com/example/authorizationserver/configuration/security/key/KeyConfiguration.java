package com.example.authorizationserver.configuration.security.key;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.time.Instant;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration {

    /**
     * Public generate key pair event on application start if not found
     * */
    @Bean
    public ApplicationListener<ApplicationReadyEvent> applicationReadyListener(
            ApplicationEventPublisher publisher, RsaKeyPairRepository repository) {
        return event -> {
            if (repository.findKeyPairs().isEmpty())
                publisher.publishEvent(new RsaKeyPairGenerationEvent(Instant.now()));
        };
    }

    /**
     * Handler generate key pair event
     * */
    @Bean
    public ApplicationListener<RsaKeyPairGenerationEvent> keyPairGenerationRequestListener(
            RsaKeyPairGenerator generator, RsaKeyPairRepository repository, @Value("${jwt.key.id}") String keyId) {
        return event -> repository.save(generator.generateKeyPair(keyId, event.getSource()));
    }

    /**
     * Encryptor
     * */
    @Bean
    public TextEncryptor textEncryptor(
            @Value("${jwt.persistence.password}") String pw,
            @Value("${jwt.persistence.salt}") String salt) {
        return Encryptors.text(pw, salt);
    }

    @Bean
    public RsaPublicKeyConverter rsaPublicKeyConverter(TextEncryptor textEncryptor) {
        return new RsaPublicKeyConverter(textEncryptor);
    }

    @Bean
    public RsaPrivateKeyConverter rsaPrivateKeyConverter(TextEncryptor textEncryptor) {
        return new RsaPrivateKeyConverter(textEncryptor);
    }

    @Bean
    public NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> delegatingOAuth2TokenGenerator(
            JwtEncoder encoder, OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        JwtGenerator generator = new JwtGenerator(encoder);
        generator.setJwtCustomizer(customizer);
        return new DelegatingOAuth2TokenGenerator(generator,
                new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }
}
