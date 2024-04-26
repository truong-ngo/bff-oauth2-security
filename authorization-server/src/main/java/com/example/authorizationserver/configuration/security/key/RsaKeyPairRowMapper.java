package com.example.authorizationserver.configuration.security.key;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class RsaKeyPairRowMapper implements RowMapper<RsaKeyPairRepository.RsaKeyPair> {

    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;

    private final RsaPublicKeyConverter rsaPublicKeyConverter;

    @Override
    public RsaKeyPairRepository.RsaKeyPair mapRow(ResultSet rs, int rowNum) throws SQLException {
        try {
            byte[] privateKeyBytes = rs.getString("private_key").getBytes();
            RSAPrivateKey privateKey = this.rsaPrivateKeyConverter.deserializeFromByteArray(privateKeyBytes);

            byte[] publicKeyBytes = rs.getString("public_key").getBytes();
            RSAPublicKey publicKey = this.rsaPublicKeyConverter.deserializeFromByteArray(publicKeyBytes);

            Instant created = new Date(rs.getDate("created").getTime()).toInstant();
            String id = rs.getString("id");

            return new RsaKeyPairRepository.RsaKeyPair(id, created, publicKey, privateKey);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
