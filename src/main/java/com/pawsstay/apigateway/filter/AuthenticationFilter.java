package com.pawsstay.apigateway.filter;

import com.pawsstay.apigateway.config.RouteValidator;
import com.pawsstay.apigateway.util.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractChangeRequestUriGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.net.URI;
import java.util.Optional;

@Component
public class AuthenticationFilter extends AbstractChangeRequestUriGatewayFilterFactory<AuthenticationFilter.Config> {
    private final Logger Logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final RouteValidator validator;
    private final JwtUtils jwtUtils;

    public AuthenticationFilter(RouteValidator validator, JwtUtils jwtUtils) {
        super(Config.class);
        this.validator = validator;
        this.jwtUtils = jwtUtils;
    }

    public static class Config {}

    @Override
    protected Optional<URI> determineRequestUri(ServerWebExchange exchange, Config config) {
        return Optional.empty();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            // 1. check up request need to validate
            if (validator.isSecured.test(exchange.getRequest())) {
                // 2. check up authorization header isExist
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    Logger.warn("missing authorization header");
                    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }

                try {
                    Logger.info("validation before");
                    // 3. validation
                    jwtUtils.validateToken(authHeader);
                    Logger.info("validation success");


                    // 在 validateToken 成功後加入：
                    String email = jwtUtils.extractEmail(authHeader);
                    Logger.info("extractEmail email {}",  email);
                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("X-User-Email", email)
                            .build();

                    // 4. 將修改後的 request 傳遞給下一個 Filter 或服務
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());

                } catch (Exception e) {
                    Logger.warn("something wrong", e);
                    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }
            return chain.filter(exchange);
        });
    }

}
