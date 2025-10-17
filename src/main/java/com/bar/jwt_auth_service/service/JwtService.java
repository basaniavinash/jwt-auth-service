package com.bar.jwt_auth_service.service;

import com.bar.jwt_auth_service.config.AuthProperties;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private final KeyConfig keys;          // your existing key holder
    private final AuthProperties props;

    public JwtService(KeyConfig keys, AuthProperties props) {
        this.keys = keys;
        this.props = props;
    }

    public String mintAccessToken(String subject, String scope, String tenantId) throws Exception {
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder()
                .issuer(props.getIssuer())
                .subject(subject)
                .audience(props.getAudience())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(props.getTokenTtlSeconds())))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", scope)
                .claim("tenant_id", tenantId)
                .build();

        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keys.signingKey().getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        var jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(keys.signingKey().toPrivateKey()));
        return jwt.serialize();
    }
}
