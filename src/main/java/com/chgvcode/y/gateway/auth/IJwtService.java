package com.chgvcode.y.gateway.auth;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

public interface IJwtService {
    public boolean isTokenValid(String token, UserDetails userDetails);

    public String extractUsername(String token);

    public Date extractExpiration(String token);
}
