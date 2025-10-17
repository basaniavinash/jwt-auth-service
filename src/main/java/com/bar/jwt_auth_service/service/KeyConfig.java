package com.bar.jwt_auth_service.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.*;
import java.util.UUID;

@Component
public class KeyConfig {
    private final RSAKey rsaJwk;
    private final JWKSet jwkSet;

    public KeyConfig() throws Exception {
        var kid = "K1-" + UUID.randomUUID();
        var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        rsaJwk = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                .privateKey((RSAPrivateKey) kp.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid)
                .build();

        jwkSet = new JWKSet(rsaJwk.toPublicJWK());
    }

    public RSAKey signingKey() { return rsaJwk; }
    public JWKSet jwkSet() { return jwkSet; }
}
