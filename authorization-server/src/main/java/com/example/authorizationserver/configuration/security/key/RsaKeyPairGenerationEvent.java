package com.example.authorizationserver.configuration.security.key;

import org.springframework.context.ApplicationEvent;

import java.time.Instant;

public class RsaKeyPairGenerationEvent extends ApplicationEvent {

    public RsaKeyPairGenerationEvent(Instant instant) {
        super(instant);
    }

    @Override
    public Instant getSource() {
        return (Instant) super.getSource();
    }
}
