package com.bff.webbff.configuration.route;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@Configuration
@EnableWebFluxSecurity
public class RouteConfig {

    private static final String API_PREFIX = "/api/";

    @Bean
    public RouteLocator gateway(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(rs -> rs
                        .path(API_PREFIX + "**")
                        .filters(f -> f
                                .tokenRelay()
                                .saveSession()
                                .rewritePath(API_PREFIX + "(?<segment>.*)", "/$\\{segment}"))
                        .uri("http://localhost:8081"))
                .route(rs -> rs
                        .path("/main.js","/@fs/**","/@vite/**","/polyfills.js","/styles.css","/favicon.ico")
                        .uri("http://localhost:4200"))
                .route(rs -> rs
                        .path("/**")
                        .filters(GatewayFilterSpec::saveSession)
                        .uri("http://localhost:4200"))
                .build();
    }
}
