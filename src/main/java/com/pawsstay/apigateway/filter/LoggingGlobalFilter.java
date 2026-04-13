package com.pawsstay.apigateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
@Slf4j
@Component
public class LoggingGlobalFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();
        long startTime = System.currentTimeMillis();

        log.info("Incoming request: {}", path);

        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            // Log the execution time after the response returns
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            log.info("Request {} completed in {} ms", path, duration);
        }));
    }
    @Override
    public int getOrder() {
        // High priority for logging
        return -1;
    }
}
