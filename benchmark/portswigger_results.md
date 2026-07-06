# RQ3 — Token analyser vs PortSwigger JWT lab classes

The analyser assesses a *captured token* offline. Server-side-only flaws (where the weakness is in the server's verification, not the token) are marked and excluded from the token-detectable denominator.

**Overall:** 7/8 lab classes surfaced by the analyser.  
**Token-detectable classes:** 6/6 detected.

| Lab | Vector | Token-detectable | Detected | Severity |
|-----|--------|------------------|----------|----------|
| 1. Auth bypass via unverified signature | Server does not verify the signature at all. | no (server-side) | ❌ | CRITICAL |
| 2. Auth bypass via flawed signature verification (none) | alg=none accepted. | yes | ✅ | CRITICAL |
| 3. Auth bypass via weak signing key | HMAC secret recoverable from a wordlist. | yes | ✅ | CRITICAL |
| 4. JWK header injection | Attacker embeds a self-signed JWK in the header. | yes | ✅ | CRITICAL |
| 5. JKU header injection | Attacker points jku at a key they control. | yes | ✅ | CRITICAL |
| 6. kid header path traversal | kid used in a path-traversal key lookup. | yes | ✅ | CRITICAL |
| 7. Algorithm confusion (RS->HS) | Server verifies an HMAC token with an RSA public key. | no (server-side) | ✅ | CRITICAL |
| 8. kid header SQL injection | kid used unsafely in a SQL key lookup. | yes | ✅ | CRITICAL |
