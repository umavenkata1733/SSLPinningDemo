# SecureNetworkingKit

`SecureNetworkingKit` is a reusable Swift Package for HTTPS networking with certificate pinning and public key pinning.

It is designed so the app layer owns presentation and view models, while the package owns network transport, trust evaluation, pin validation, and pinning logs.

## Architecture

```text
Main SwiftUI App
    -> ViewModel
        -> APIClientProtocol
            -> SecureAPIClient
                -> SSLPinningURLSessionDelegate
                    -> CertificatePinningValidator
                    -> PublicKeyPinningValidator
```

## What This Package Protects

SSL pinning protects against a malicious or misconfigured TLS chain that would otherwise pass standard platform trust validation. The package always runs Apple's default SSL validation first, then applies your configured pin.

This package does not replace authentication. Production apps should still use server-side auth, short-lived tokens, Keychain storage, risk checks, and secure backend authorization.

## Production Features

- Swift Package Manager library.
- Certificate pinning using bundled DER `.cer` resources.
- Public key pinning using SHA-256 Base64 hashes.
- Multiple pinned hosts.
- Multiple certificates and public key hashes per host for rotation.
- Default SSL validation before pin validation.
- Hostname validation with `SecPolicyCreateSSL`.
- `SecTrustEvaluateWithError`.
- `URLSessionDelegate` and `URLSessionTaskDelegate`.
- Async/await networking.
- Ephemeral `URLSessionConfiguration`.
- Configurable request and resource timeouts.
- Debug-only console logs by default.

## Configure Pins

Use multiple pins in production so certificate or key rotation does not break all installed apps.

```swift
let configuration = SSLPinningConfiguration(
    pinnedHosts: [
        "api.example.com": PinnedHostConfiguration(
            certificateResourceNames: [
                "api-example-current",
                "api-example-next"
            ],
            publicKeyHashes: [
                "current-public-key-hash",
                "backup-public-key-hash"
            ]
        )
    ],
    timeoutIntervalForRequest: 30,
    timeoutIntervalForResource: 60
)
```

## Multiple Hosts

Each host gets its own pin policy. A request to `api.example.com` is checked only against the pins for `api.example.com`. A request to `auth.example.com` is checked only against the pins for `auth.example.com`.

```swift
let configuration = SSLPinningConfiguration(
    pinnedHosts: [
        "api.example.com": PinnedHostConfiguration(
            certificateResourceNames: [
                "api-current",
                "api-next"
            ],
            publicKeyHashes: [
                "api-current-public-key-hash",
                "api-backup-public-key-hash"
            ]
        ),
        "auth.example.com": PinnedHostConfiguration(
            certificateResourceNames: [
                "auth-current",
                "auth-next"
            ],
            publicKeyHashes: [
                "auth-current-public-key-hash",
                "auth-backup-public-key-hash"
            ]
        )
    ]
)
```

If a host is not present in `pinnedHosts`, the request is cancelled during the authentication challenge.

```text
Configured:
api.example.com
auth.example.com

Allowed:
https://api.example.com/...
https://auth.example.com/...

Cancelled:
https://unknown.example.com/...
```

Certificate files must be placed in:

```text
Sources/SecureNetworkingKit/Resources/
```

`Package.swift` must include:

```swift
resources: [
    .process("Resources")
]
```

The package loads certificates using:

```swift
Bundle.module
```

## Create Client

```swift
let client = SecureAPIClient(
    endpoint: URL(string: "https://api.example.com/v1/profile")!,
    configuration: configuration,
    logger: SSLPinningLogger(isEnabled: false)
)
```

For authenticated APIs, pass tokens per request:

```swift
var request = URLRequest(url: URL(string: "https://api.example.com/v1/profile")!)
request.httpMethod = "GET"
request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

let response = try await client.send(request, using: .publicKey)
```

Store auth tokens in Keychain. Do not hardcode tokens or private keys in the app bundle.

## Why This Is Secure

The package performs two checks before a request is allowed:

```text
1. Default Apple SSL validation
   Checks certificate chain, expiry, hostname, and system trust.

2. Pin validation
   Checks that the trusted server also matches your bundled certificate
   or one of your expected public key hashes.
```

This means a request is allowed only when normal TLS validation passes and the server matches your configured pin.

```text
Valid CA certificate but wrong key       -> cancelled
Expired or invalid certificate           -> cancelled
Correct pin but invalid TLS trust chain   -> cancelled
Correct TLS trust and correct pin         -> allowed
```

The public key hash is not a secret. It is safe to ship in the app because it is derived from the server public certificate. The security comes from detecting if the server key changes unexpectedly. Do not ship private keys, API secrets, or long-lived tokens in the app bundle.

## Certificate Pinning

Certificate pinning compares the exact server certificate bytes with one of the bundled `.cer` files.

Pros:

- Simple to reason about.
- Very strict.

Cons:

- Certificate renewal usually requires an app update unless the next certificate is already bundled.
- Operationally fragile if your CA rotates or reissues certificates.

Use certificate pinning only when you have a strong certificate rotation process.

## Public Key Pinning

Public key pinning extracts the server public key, converts it to SubjectPublicKeyInfo DER, hashes it with SHA-256, and compares it with one of your configured Base64 hashes.

Pros:

- Usually safer operationally than certificate pinning.
- Allows certificate renewal when the key pair stays the same.
- Supports current and backup key hashes.

Cons:

- If you lose the private key and did not ship a backup pin, older app versions can be locked out.

Recommended production default: public key pinning with at least two hashes, current and backup.

## OpenSSL Commands

Get `.cer` directly:

```sh
openssl s_client -showcerts -connect sha256.badssl.com:443 -servername sha256.badssl.com </dev/null 2>/dev/null \
| openssl x509 -outform DER > sha256-badssl.cer
```

Convert `.pem` to `.cer`:

```sh
openssl x509 -in sha256-badssl.pem -outform DER -out sha256-badssl.cer
```

Get public key hash:

```sh
openssl s_client -connect sha256.badssl.com:443 -servername sha256.badssl.com </dev/null 2>/dev/null \
| openssl x509 -pubkey -noout \
| openssl pkey -pubin -outform DER \
| openssl dgst -sha256 -binary \
| openssl base64
```

## Production Checklist

- Pin only hosts you own.
- Prefer public key pinning with current and backup hashes.
- Keep certificate pinning only if your release and certificate rotation process is mature.
- Disable detailed pinning logs in Release.
- Store tokens in Keychain.
- Never ship a reusable private key in the app bundle.
- Use Secure Enclave generated keys only for device-bound authentication.
- Add backend monitoring for pinning failures before enforcing pins widely.
- Test pin failure paths before release.
- Keep at least one older app version compatible during certificate rotation.

## Replacing badssl With Production

1. Replace `https://sha256.badssl.com/` with your API URL.
2. Replace `sha256-badssl.cer` with your production certificate if using certificate pinning.
3. Replace the public key hash with your production hash.
4. Add a backup public key hash before release.
5. Update `SSLPinningConfiguration` with your production host.

Example:

```swift
let configuration = SSLPinningConfiguration(
    pinnedHosts: [
        "api.yourcompany.com": PinnedHostConfiguration(
            certificateResourceNames: ["api-yourcompany-current"],
            publicKeyHashes: [
                "production-current-key-hash",
                "production-backup-key-hash"
            ]
        )
    ]
)
```
