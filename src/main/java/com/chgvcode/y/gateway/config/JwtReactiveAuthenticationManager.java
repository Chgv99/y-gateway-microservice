package com.chgvcode.y.gateway.config;

import java.util.List;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.chgvcode.y.gateway.auth.JwtService;

import reactor.core.publisher.Mono;

@Component
public class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtService jwtService;

    public JwtReactiveAuthenticationManager(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String token = authentication.getCredentials().toString();

        if (jwtService.validateToken(token)) {
            String username = jwtService.extractUsername(token);
            String role = jwtService.extractRole(token);

            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

            User principal = new User(username, "", authorities);
            return Mono.just(new UsernamePasswordAuthenticationToken(principal, token, authorities));
        }

        return Mono.empty();
    }
    
}
