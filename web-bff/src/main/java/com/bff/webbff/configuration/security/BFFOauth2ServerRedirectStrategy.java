package com.bff.webbff.configuration.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Collection;
import java.util.Optional;

/**
 * Change rp logout method status
 * */
@RequiredArgsConstructor
public class BFFOauth2ServerRedirectStrategy implements ServerRedirectStrategy {

    private final HttpStatus defaultStatus;

    /**
     * Change response status to 2** to prevent auto redirect so SPA can manually call /connect/logout to auth server
     * */
    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            final HttpStatus status = Optional
                    .ofNullable(exchange.getRequest().getHeaders().get("X-RESPONSE-STATUS")).stream().flatMap(Collection::stream)
                    .filter(StringUtils::hasLength)
                    .findAny()
                    .map(statusStr -> {
                        try {
                            final int statusCode = Integer.parseInt(statusStr);
                            return HttpStatus.valueOf(statusCode);
                        } catch (NumberFormatException e) {
                            return HttpStatus.valueOf(statusStr.toLowerCase());
                        }
                    })
                    .orElse(defaultStatus);
            response.setStatusCode(status);
            response.getHeaders().setLocation(location);
        });
    }
}
