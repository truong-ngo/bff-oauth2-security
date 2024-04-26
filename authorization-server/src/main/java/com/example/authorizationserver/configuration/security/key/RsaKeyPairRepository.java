package com.example.authorizationserver.configuration.security.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

/**
 * Rsa key pair repository
 * */
public interface RsaKeyPairRepository {

    List<RsaKeyPair> findKeyPairs();

    void save(RsaKeyPair rsaKeyPair);

    /**
     * Key pair entity
     * */
    record RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {}

}
