package com.example.authorizationserver.configuration.security.key;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

/**
 * Key pair jdbc repository implement
 * */
@Component
@RequiredArgsConstructor
public class JdbcRsaKeyPairRepository implements RsaKeyPairRepository {

    private final JdbcTemplate jdbc;

    private final RsaPublicKeyConverter rsaPublicKeyConverter;

    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;

    private final RowMapper<RsaKeyPair> keyPairRowMapper;

    @Override
    public List<RsaKeyPair> findKeyPairs() {
        return this.jdbc.query("select * from rsa_key_pairs order by created desc", this.keyPairRowMapper);
    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        String sql = """
                insert into rsa_key_pairs (id, private_key, public_key, created) values (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE id = id;
                """;
        try (
                OutputStream privateBaos = new ByteArrayOutputStream();
                OutputStream publicBaos = new ByteArrayOutputStream()
        ) {
            this.rsaPrivateKeyConverter.serialize(rsaKeyPair.privateKey(), privateBaos);
            this.rsaPublicKeyConverter.serialize(rsaKeyPair.publicKey(), publicBaos);
            int updated = this.jdbc.update(sql,
                    rsaKeyPair.id(),
                    privateBaos.toString(),
                    publicBaos.toString(),
                    new Date(rsaKeyPair.created().toEpochMilli()));
            Assert.state(updated == 0 || updated == 1, "no more than one record should have been updated");
        }
        catch (IOException e) {
            throw new IllegalArgumentException("there's been an exception", e);
        }
    }
}
