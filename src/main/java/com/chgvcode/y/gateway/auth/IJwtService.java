package com.chgvcode.y.gateway.auth;

import java.util.Date;

public interface IJwtService {
    public String extractUsername(String token);

    public Date extractExpiration(String token);

    public String extractRole(String token);

    public Boolean validateToken(String token);
}
