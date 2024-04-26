package com.bff.webresource.controller;

import com.bff.webresource.service.ResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class ResourceController {

    private final ResourceService service;

    @GetMapping("/")
    public Map<String, String> getResource() {
        return service.getData();
    }

    @GetMapping("/authenticated")
    public Map<String, String> getPublicResource() {
        return service.getPublicData();
    }
}
