package com.bff.webresource.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ResourceService {

    public Map<String, String> getData() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String subject = authentication.getName();
        return Map.of("subject", subject);
    }

    public Map<String, String> getPublicData() {
        return Map.of("public-data", "public data");
    }
}
