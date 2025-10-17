package com.bar.jwt_auth_service.controller;

import com.bar.jwt_auth_service.service.KeyConfig;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class JwksController {
    private final KeyConfig keys;
    public JwksController(KeyConfig keys) { this.keys = keys; }

    @GetMapping("/jwks.json")
    public Map<String, Object> jwks() {
        JWKSet set = keys.jwkSet();
        return set.toJSONObject(); // { "keys": [ ... ] }
    }
}
