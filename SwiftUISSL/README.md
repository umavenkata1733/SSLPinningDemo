# SSLPinningDemo

SwiftUI demo project showing certificate pinning and public key pinning with a reusable Swift Package named `SecureNetworkingKit`.

The package has been hardened for production-style use with multiple pinned hosts, multiple pins per host for rotation, configurable timeouts, Debug-only logs by default, async `URLRequest` support, and SwiftPM tests.

Package documentation:

`SecureNetworkingKit/README.md`

## Test Endpoint

`https://sha256.badssl.com/`

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

## Setup Steps in Xcode

1. Open `SSLPinningDemo.xcodeproj`.
2. Select the `SSLPinningDemo` scheme.
3. Choose an iOS simulator or device.
4. Build and run.
5. Use the picker to switch between `Certificate Pinning` and `Public Key Pinning`.
6. Tap `Call API`.
7. Watch the Xcode console for detailed SSL validation and pinning logs.

## Expected Xcode Console Logs

Certificate pinning path:

```text
[SSL Pinning] Request started
[SSL Pinning] URL: https://sha256.badssl.com/
[SSL Pinning] Pinning type: Certificate Pinning
[SSL Pinning] Authentication challenge received
[SSL Pinning] Host name: sha256.badssl.com
[SSL Pinning] Default SSL validation started
[SSL Pinning] Default SSL validation passed
[SSL Pinning] Certificate pinning started
[SSL Pinning] Server certificate extracted
[SSL Pinning] Local certificate loaded: sha256-badssl.cer
[SSL Pinning] Certificate match passed
[SSL Pinning] Request allowed
[SSL Pinning] HTTP status code: 200
[SSL Pinning] Response size: ... bytes
```

Public key pinning path:

```text
[SSL Pinning] Request started
[SSL Pinning] URL: https://sha256.badssl.com/
[SSL Pinning] Pinning type: Public Key Pinning
[SSL Pinning] Authentication challenge received
[SSL Pinning] Host name: sha256.badssl.com
[SSL Pinning] Default SSL validation started
[SSL Pinning] Default SSL validation passed
[SSL Pinning] Public key pinning started
[SSL Pinning] Server public key extracted
[SSL Pinning] Public key hash generated
[SSL Pinning] Expected hash: chBKGC2E4cdpgMD2jlsFLLJvoujxm9EUKcSlUiZN6Rc=
[SSL Pinning] Actual hash: chBKGC2E4cdpgMD2jlsFLLJvoujxm9EUKcSlUiZN6Rc=
[SSL Pinning] Pinning passed
[SSL Pinning] Request allowed
[SSL Pinning] HTTP status code: 200
[SSL Pinning] Response size: ... bytes
```

## Certificate Pinning vs Public Key Pinning

Certificate pinning compares the full DER certificate returned by the server with a bundled local `.cer` file. It is strict: when the server certificate renews or changes, the bundled certificate must also be replaced.

Public key pinning compares a SHA-256 hash of the server certificate public key. It is usually more flexible because a certificate can be renewed while keeping the same key pair. This demo hashes the RSA 2048 public key with the ASN.1 SubjectPublicKeyInfo header so the Swift hash matches the OpenSSL command above.

## Replacing sha256.badssl.com with a Production API Domain

Create a production configuration with your host, current pin, and backup pin:

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

Replace the bundled certificate at:

`SecureNetworkingKit/Sources/SecureNetworkingKit/Resources/sha256-badssl.cer`

Then update `SecureAPIClient` to call your production endpoint. Prefer public key pinning with current and backup hashes for production. Do not hardcode private keys or tokens in the app.
