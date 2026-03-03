package com.pawsstay.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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

    public String extractEmail(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public Map<String, String> extractUserDetail(String token) {
        Claims claims = getClaims(token);
        Map<String, String> userDetail = new HashMap<>();
        userDetail.put("email", claims.getSubject());
        userDetail.put("userId", claims.get("userId", String.class));
        userDetail.put("role", claims.get("role", String.class));
        userDetail.put("username", claims.get("username", String.class));
        return userDetail;
    }

}
