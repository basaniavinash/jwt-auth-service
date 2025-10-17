import base64, json, time

header = {"alg":"RS256","typ":"JWT","kid":"K1"}
iat = int(time.time())
exp = iat + 3600
payload = {
  "iss":"https://auth.stormhook.local",
  "sub":"client:tenant-admin-42",
  "aud":"https://api.stormhook.local",
  "scope":"admin:tenants:read",
  "tenant_id":"T987",
  "iat": iat,
  "exp": exp,
  "jti": "b3d1a2b8-9c64-4a8d-8f6f-2c9a6e9f1234"
}


def b64url(b):
  return base64.urlsafe_b64encode(b).decode().rstrip("=")


print("HEADER_B64URL=", b64url(json.dumps(header, separators=(',',':')).encode()))
print("PAYLOAD_B64URL=", b64url(json.dumps(payload, separators=(',',':')).encode()))

