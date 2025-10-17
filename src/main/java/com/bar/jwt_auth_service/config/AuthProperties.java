package com.bar.jwt_auth_service.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import java.util.*;

@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
    private String issuer;
    private String audience;
    private long tokenTtlSeconds = 3600;

    public static class Client {
        private String secret;                 // BCrypt hash
        private List<String> allowedScopes = new ArrayList<>();
        private String tenantId;

        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public List<String> getAllowedScopes() { return allowedScopes; }
        public void setAllowedScopes(List<String> allowedScopes) { this.allowedScopes = allowedScopes; }
        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    }

    private Map<String, Client> clients = new HashMap<>();

    // getters/setters
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public long getTokenTtlSeconds() { return tokenTtlSeconds; }
    public void setTokenTtlSeconds(long tokenTtlSeconds) { this.tokenTtlSeconds = tokenTtlSeconds; }
    public Map<String, Client> getClients() { return clients; }
    public void setClients(Map<String, Client> clients) { this.clients = clients; }
}