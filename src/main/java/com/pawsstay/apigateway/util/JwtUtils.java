package com.pawsstay.apigateway.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    @Value("${app.jwt.secret}")
    private String SECRET_KEY;
    private SecretKey key;
    @PostConstruct
    public void init() {
        if (this.SECRET_KEY == null) {
            throw new RuntimeException("JWT Secret Key is not configured!");
        }
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public void validateToken(final String token) {
        // 解析 Token，如果過期、簽章錯誤、或格式不對，Jwts 會直接拋出 Exception
        Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }
}
