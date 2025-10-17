package com.bar.jwt_auth_service.controller;

import com.bar.jwt_auth_service.config.AuthProperties;
import com.bar.jwt_auth_service.service.JwtService;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
public class TokenController {
    private final JwtService jwtService;
    private final AuthProperties props;
    private final PasswordEncoder encoder;

    public TokenController(JwtService jwtService, AuthProperties props, PasswordEncoder encoder) {
        this.jwtService = jwtService;
        this.props = props;
        this.encoder = encoder;
    }

    @PostMapping(path="/oauth/token", consumes=MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> token(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam(defaultValue = "client_credentials") String grant_type,
            @RequestParam String scope,
            @RequestParam(required = false, name="tenant_id") String tenantIdParam) throws Exception {

        if (!"client_credentials".equals(grant_type)) {
            return oauthError(400, "unsupported_grant_type");
        }
        if (authorization == null || !authorization.startsWith("Basic ")) {
            return withWwwAuth(oauthError(401, "invalid_client"));
        }

        // ----- decode Basic header -----
        var b64 = authorization.substring("Basic ".length());
        var decoded = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
        var parts = decoded.split(":", 2);
        if (parts.length != 2) return withWwwAuth(oauthError(401, "invalid_client"));

        var clientId = parts[0];
        var secret = parts[1];

        // ----- lookup client -----
        var client = props.getClients().get(clientId);
        if (client == null || client.getSecret() == null) {
            return withWwwAuth(oauthError(401, "invalid_client"));
        }
        if (!encoder.matches(secret, client.getSecret())) {
            return withWwwAuth(oauthError(401, "invalid_client"));
        }

        // ----- scope check (support space-delimited list) -----
        var requested = new HashSet<>(Arrays.asList(scope.trim().split("\\s+")));
        var allowed = new HashSet<>(client.getAllowedScopes());
        if (!allowed.containsAll(requested)) {
            return oauthError(400, "invalid_scope");
        }

        // ----- tenant scoping -----
        var effectiveTenant = (tenantIdParam != null && !tenantIdParam.isBlank())
                ? tenantIdParam
                : client.getTenantId();

        var token = jwtService.mintAccessToken("client:" + clientId, String.join(" ", requested), effectiveTenant);

        return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "Bearer",
                "expires_in", props.getTokenTtlSeconds()
        ));
    }

    private static ResponseEntity<Map<String,String>> oauthError(int status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
    private static ResponseEntity<Map<String,String>> withWwwAuth(ResponseEntity<Map<String,String>> resp) {
        return ResponseEntity.status(resp.getStatusCode())
                .headers(h -> h.add(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"token\""))
                .body(resp.getBody());
    }
}
