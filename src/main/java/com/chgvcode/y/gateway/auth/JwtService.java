package com.chgvcode.y.gateway.auth;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final SecretKey key;

    public JwtService(@Value("${security.jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public Claims parseToken(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token) {
        Claims claims = parseToken(token);
        return claims.getExpiration().after(new Date());
    }

    public String getUsername(Claims claims) {
        return claims.getSubject();
    }

    public String getUserUuid(Claims claims) {
        return claims.get("userUuid", String.class);
    }

    public String getRoles(Claims claims) {
        return claims.get("roles", String.class); // or List -> String.join
    }
}
