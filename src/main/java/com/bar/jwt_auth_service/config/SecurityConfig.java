package com.bar.jwt_auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // disable CSRF for stateless API endpoints
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/oauth/token", "/.well-known/**")
                )
                // allow open access to token + jwks, block everything else
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/oauth/token", "/.well-known/**").permitAll()
                        .anyRequest().denyAll()
                )
                // stateless: no sessions or cookies
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // you can disable default login form
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(form -> form.disable());

        return http.build();
    }
}
