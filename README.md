# smolcurl

This project is a minimal, vertical implementation of the various layers involved in making an HTTPS request. The project is purely for learning purposes and should not be used for anything seriouse or secure. The goal was roughly the minimum implementation necessary to make an HTTPS GET request to example.com. 


### What's implemented

- **DNS resolution**: recursive resolver that walks the hierarchy from a root name server down through delegations, with no reliance on the OS resolver (A records only, UDP only)
- **TLS 1.3 handshake**: full client handshake (ClientHello → ServerHello → EncryptedExtensions → Certificate → CertificateVerify → Finished → client Finished), limited to the `TLS_CHACHA20_POLY1305_SHA256` cipher suite and the `x25519` key share group
- **Crypto primitives**: SHA-256, HMAC, HKDF (extract/expand), ChaCha20-Poly1305 AEAD, X25519, and ECDSA P-256 signature verification — all implemented from the relevant RFCs rather than wrapping a crypto crate
- **Record/message framing**: correct handling of records and handshake messages as independently framed (one record can carry several handshake messages, and a message can span multiple records)
- **Leaf certificate verification**: `CertificateVerify` signature checked with the custom ECDSA P-256 implementation
- **SNI and hostname/SAN validation**: server name sent in ClientHello, leaf certificate's SAN checked against the requested hostname (DNS name or IP)
- **TLS alerts**: `close_notify` handled as a graceful end-of-stream; other alerts surfaced as errors
- **HTTP/1.1**: GET requests, response status line/header parsing, and body reads via `Content-Length` or a trailing connection close

### What's left to do

- Custom TCP transport: still using `std::net::TcpStream`; a fully custom vertical integration would mean no `std` networking at all, down to raw sockets
- Chain-of-trust verification: walking the chain up to a trust anchor is currently delegated to `x509-parser`/`ring` since real-world chains mix signature algorithms (RSA, P-256, P-384) the project's crypto primitives don't cover
- Decode `Transfer-Encoding: chunked` bodies properly (currently passed through as raw chunk-framed bytes)
- Support TLS records larger than the caller's read buffer (currently assumes a decrypted record always fits in one `Read::read` call)
- `HelloRetryRequest` handling (currently a hard failure)
- Additional cipher suites and key-share groups beyond ChaCha20-Poly1305/X25519 (e.g. AES-GCM, P-256 key exchange)
- Session resumption / `NewSessionTicket` reuse (tickets are currently received and discarded)
- HTTP methods beyond GET, request bodies, and redirect following
- IPv6 (`AAAA`) support and DNS-over-TCP fallback for truncated responses in the resolver
- 0-RTT, ALPN, and client certificate support

### Usage

```
smolcurl https://example.com

sending request: GET https example.com 443 / {"Connection": "close", "Host": "example.com:443"}
querying: 198.41.0.4
querying: 192.41.162.30
querying: 108.162.192.162
resolved example.com to 172.66.147.243
opened connection ...:57434 - 172.66.147.243:443
sending client hello: Handshake([ClientHello(4867, [SupportedVersions([772]), SupportedGroups([29]), KeyShare(29, [41, 155, 204, 218, 67, 149, 230, 141, 47, 162, 212, 63, 237, 181, 121, 109, 173, 221, 68, 14, 191, 19, 249, 160, 10, 96, 77, 22, 89, 218, 70, 9]), SignatureAlgorithms([1027]), ServerName("example.com")])])
received server hello
received change cipher spec
unsupported extension type in encrypted extensions: 0
received encrypted extensions message
received certificate message
received certificate verify message
received finished message
received response: HTTP/1.1 200 Some("OK") {"age": "9954", "date": "Fri, 13 Nov 2026 21:01:56 GMT", "allow": "GET, HEAD", "transfer-encoding": "chunked", "connection": "close", "content-type": "text/html; charset=utf-8", "last-modified": "Fri, 13 Nov 2026 18:12:01 GMT", "server": "cloudflare", "accept-ranges": "bytes", "cf-cache-status": "HIT", "cf-ray": "a5a0b6e9a9941e19-YVR", "alt-svc": "h3=\":443\"; ma=86400"} 241
<!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewport content="width=device-width,initial-scale=1"><title>Example Domain</title><style>html{color-scheme:light dark;background:light-dark(#eee,#222)}body{font:16px/1.6 system-ui,sans-serif;max-width:26em;margin:auto;padding:25vh 2em 2em;text-align:center}</style></head><body><p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p><script src=/s.js></script></body></html>

0
```


