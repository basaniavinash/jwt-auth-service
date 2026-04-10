# JWT Auth Service

A stateless OAuth 2.0 token issuer built with Spring Boot and Java 21. Issues RS256-signed JWTs for the client credentials flow — no database, no session storage, pure cryptographic token generation.

---

## What it does

| Feature | Detail |
|---------|--------|
| **Token issuance** | `POST /oauth2/token` — validates HTTP Basic credentials, returns RS256-signed JWT |
| **Scope enforcement** | Per-client scope restrictions; requested scopes checked against allowed list at mint time |
| **Multi-tenancy** | `tenant_id` embedded as a custom JWT claim; downstream services isolate data by claim |
| **Client management** | Clients defined in application properties with BCrypt-hashed secrets — no DB required |

---

## Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Java 21, Spring Boot 3.5 |
| Token signing | Nimbus JOSE + JWT (RS256) |
| Auth framework | Spring Security, OAuth2 Resource Server |
| Secret hashing | BCrypt (Spring Security crypto) |

---

## Token format

```json
{
  "iss": "https://auth.example.com",
  "sub": "client-id",
  "aud": "api.example.com",
  "scope": "catalog:read orders:write",
  "tenant_id": "acme-corp",
  "iat": 1700000000,
  "exp": 1700003600
}
```

Signed with RS256. The private key never leaves the service; downstream services validate with the public key only.

---

## Design decisions

### Stateless by design

No database lookup on every token request. Clients are loaded from config at startup and held in memory. This means zero DB latency on the hot path and no single point of failure from a DB outage.

**Trade-off:** Revoking a client requires a redeploy. Acceptable for internal service-to-service auth where clients are infrastructure, not end users.

### RS256 over HS256

Asymmetric signing means downstream services can validate tokens without sharing a secret. Each service only needs the public key — compromising a downstream service doesn't expose the signing key.

### Scope-at-mint enforcement

A client can only request scopes it's explicitly allowed. The token issuer rejects over-scoped requests at creation time rather than delegating that check to each downstream service.

---

## Running locally

```bash
# Generate RSA key pair (for dev only)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Configure application.yml with client definitions
./mvnw spring-boot:run
```

```bash
# Get a token
curl -u client-id:client-secret \
  -d "grant_type=client_credentials&scope=catalog:read" \
  http://localhost:8080/oauth2/token
```
