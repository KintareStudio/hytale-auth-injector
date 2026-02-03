# Omni-Auth: Decentralized Authentication for Hytale

> Technical specification for implementing self-contained JWT tokens with embedded cryptographic keys.
>
> **Credits:** Based on the original implementation by [@soyelmismo](https://github.com/soyelmismo) in [RusTale](https://github.com/soyelmismo/RusTale).

## Overview

**Omni-Auth** enables decentralized authentication by embedding cryptographic keys directly into JWT tokens. This allows clients to generate their own identity without relying on a centralized authentication server.

Standard Hytale Auth relies on a centralized Authority (Issuer) that signs tokens. The Game Server fetches the Public Key from that Authority via a `/.well-known/jwks.json` endpoint to validate signatures.

**Omni-Auth** reverses this: The **token itself contains the key** required to validate it. When a patched server (using `DualAuthPatcher`) sees a token with an embedded `jwk` header, it uses that embedded key to validate the signature instead of asking an external server.

## Token Structure

### JWT Header with Embedded JWK

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "BASE64URL_PUBLIC_KEY",
    "d": "BASE64URL_PRIVATE_KEY",
    "use": "sig"
  }
}
```

| Field | Description |
|-------|-------------|
| `alg` | Algorithm: `EdDSA` (Edwards-curve Digital Signature Algorithm) |
| `typ` | Token type: `JWT` |
| `jwk.kty` | Key Type: `OKP` (Octet Key Pair) |
| `jwk.crv` | Curve: `Ed25519` |
| `jwk.x` | Public key (32 bytes, Base64URL no-pad) |
| `jwk.d` | Private key (32 bytes, Base64URL no-pad) |
| `jwk.use` | Usage: `sig` (signature) |

### JWT Payload (Claims)

```json
{
  "sub": "player-uuid",
  "username": "PlayerName",
  "iss": "http://127.0.0.1:12345",
  "aud": "hytale-server",
  "iat": 1706000000,
  "exp": 1706003600,
  "scope": "hytale:client",
  "omni": true
}
```

| Claim | Description |
|-------|-------------|
| `sub` | Player UUID |
| `username` | Player display name |
| `iss` | Issuer URL (typically loopback for Omni-Auth) |
| `aud` | Audience: `hytale-server` |
| `iat` | Issued at timestamp |
| `exp` | Expiration timestamp |
| `scope` | Required scope: `hytale:client` |
| `omni` | Optional flag indicating Omni-Auth token |

## Implementation

### Step 1: Generate Ed25519 KeyPair

Generate a random Ed25519 keypair. The same keypair should be used consistently for a player's session.

**Requirements:**
- Algorithm: EdDSA (Edwards-curve Digital Signature Algorithm)
- Curve: Ed25519
- Key size: 32 bytes (256 bits)

### Step 2: Construct the JWK Object

Create a JSON Web Key containing both public and private components:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "BASE64URL_STR",
  "d": "BASE64URL_STR",
  "use": "sig"
}
```

**Important:** Values for `x` and `d` MUST be Base64URL encoded **without padding** (RFC 4648).

### Step 3: Build and Sign the JWT

1. Serialize header (with embedded JWK)
2. Serialize payload
3. Concatenate: `base64url(header) + "." + base64url(payload)`
4. Sign with Ed25519 private key
5. Append: `"." + base64url(signature)`

Final token: `header.payload.signature`

## Code Examples

### Python

```python
#!/usr/bin/env python3
"""Generate Omni-Auth JWT tokens."""

import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def generate_omni_token(player_uuid: str, username: str, issuer: str = "http://127.0.0.1:12345") -> str:
    # Generate Ed25519 keypair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get raw key bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Build JWK
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode(public_bytes),
        "d": b64url_encode(private_bytes),
        "use": "sig",
        "alg": "EdDSA"
    }

    # JWT Header
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "jwk": jwk
    }

    # JWT Payload
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": player_uuid,
        "aud": "hytale-server",
        "iat": now,
        "exp": now + 3600,
        "username": username,
        "omni": True,
        "scope": "hytale:client"
    }

    # Encode and sign
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    signature = private_key.sign(signing_input)
    signature_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"

# Usage
token = generate_omni_token("550e8400-e29b-41d4-a716-446655440000", "MyPlayer")
print(token)
```

### Node.js

```javascript
const crypto = require('crypto');

function generateOmniToken(playerUuid, username, issuer = 'http://127.0.0.1:12345') {
    // Generate Ed25519 keypair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

    // Export keys as JWK
    const privateJwk = privateKey.export({ format: 'jwk' });
    const publicJwk = publicKey.export({ format: 'jwk' });

    // Build embedded JWK
    const jwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: publicJwk.x,
        d: privateJwk.d,
        use: "sig",
        alg: "EdDSA"
    };

    // JWT Header
    const header = {
        alg: "EdDSA",
        typ: "JWT",
        jwk: jwk
    };

    // JWT Payload
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: issuer,
        sub: playerUuid,
        aud: "hytale-server",
        iat: now,
        exp: now + 3600,
        username: username,
        omni: true,
        scope: "hytale:client"
    };

    // Encode
    const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const headerB64 = b64url(header);
    const payloadB64 = b64url(payload);
    const signingInput = `${headerB64}.${payloadB64}`;

    // Sign
    const signature = crypto.sign(null, Buffer.from(signingInput), privateKey);
    const signatureB64 = signature.toString('base64url');

    return `${signingInput}.${signatureB64}`;
}

// Usage
const token = generateOmniToken('550e8400-e29b-41d4-a716-446655440000', 'MyPlayer');
console.log(token);
```

### Rust (RusTale Reference)

Based on RusTale's implementation in `launcher/src/game/auth.rs`:

```rust
use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn generate_omni_token(uuid: &str, username: &str, issuer: &str) -> String {
    // Generate keypair from random seed
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();

    // Build JWK
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        "d": URL_SAFE_NO_PAD.encode(signing_key.as_bytes()),
        "use": "sig",
        "alg": "EdDSA"
    });

    // Header with embedded JWK
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "jwk": jwk
    });

    // Payload
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = serde_json::json!({
        "iss": issuer,
        "sub": uuid,
        "aud": "hytale-server",
        "iat": now,
        "exp": now + 3600,
        "username": username,
        "omni": true,
        "scope": "hytale:client"
    });

    // Encode and sign
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{}.{}", signing_input, signature_b64)
}
```

## Server-Side Validation

When a patched server receives an Omni-Auth token:

1. **Parse Header**: Extract the JWT header
2. **Detect Embedded JWK**: Check if `header.jwk` exists
3. **Extract Public Key**: Use `header.jwk.x` (public key) for validation
4. **Verify Signature**: Validate against the embedded public key
5. **Cache Key**: Store in transient cache keyed by player UUID

The server **ignores the private key** (`d`) - it only needs the public key to verify. The private key is included for completeness and to allow client-side re-signing if needed.

## Security Considerations

### Trust Model

Omni-Auth operates on a **self-signed** trust model:
- Any client can generate valid tokens
- The server trusts the embedded key
- No central authority verification

### Server Configuration

Use `HYTALE_TRUST_ALL_ISSUERS` to control acceptance:

| Value | Behavior |
|-------|----------|
| `true` (default) | Accept all Omni-Auth tokens |
| `false` | Reject Omni-Auth unless issuer in `HYTALE_TRUSTED_ISSUERS` |

### Cache Isolation

Each player's JWK is cached separately by UUID to prevent key collisions:
- Player A with `127.0.0.1` issuer and Key1
- Player B with `127.0.0.1` issuer and Key2
- Both work simultaneously (cache keyed by UUID, not issuer)

## Testing

Use the CI test script to generate test tokens:

```bash
python3 .github/scripts/generate-omni-token.py \
  --uuid "550e8400-e29b-41d4-a716-446655440000" \
  --username "TestPlayer" \
  --issuer "http://127.0.0.1:12345"
```

Options:
- `--invalid-sig`: Generate token with corrupted signature (for rejection testing)
- `--no-jwk`: Generate token without embedded JWK (for fallback testing)
- `--output debug`: Show decoded token contents

## References

- [RFC 7515 - JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 8037 - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
- [Ed25519 - High-speed high-security signatures](https://ed25519.cr.yp.to/)

## Related

- [DualAuthPatcher README](README.md) - Main patcher documentation
- [hytale-auth-server](https://github.com/sanasol/hytale-auth-server) - F2P auth server
- [RusTale](https://github.com/soyelmismo/RusTale) - Original Omni-Auth implementation by @soyelmismo
