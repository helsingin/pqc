# Reproducible TLS inspection

`pqc.InspectTLS` observes a TLS handshake without sending application data. It is
not a general-purpose dialer and does not establish that a service is safe.

Options now include explicit `CurvePreferences`, `MinVersion`/`MaxVersion`,
`NextProtos`, and `DialAddress`. A dial override must be numeric IP:port; SNI and
certificate hostname verification still use `ServerName` or the original target.
Callers can resolve and approve an address before connecting, without a second
DNS lookup. Destination authorization, rate limits and DNS policy belong to the
calling application.

Explicit groups and the legacy `PQC` convenience flag cannot be combined. The
convenience flag retains its hybrid preferences and classical fallback. To test
a particular group, supply only that group and constrain the TLS version. A
failed handshake is inconclusive about the cause, not proof the server lacks
an algorithm. Empty groups use Go's defaults and are not an explicit profile.

Reports retain the connected remote address, explicit offered groups, version
bounds, ALPN and the presented public certificates, including DER, certificate and public-key fingerprints, serial numbers, algorithm OIDs
and recognised key parameters. Certificate trust is evaluated on that same
connection; a trust failure no longer triggers a second handshake against a
potentially different frontend. Such results have `Verified=false` and an
explicit verification error. No application data is sent on an untrusted session.
TLS handshake signature checks are still performed by Go's TLS implementation.

Key exchange, certificate public-key algorithm and certificate issuer-signature
algorithm are distinct. Go's public connection state does not expose the selected
handshake signature scheme; do not substitute the certificate signature for it.
Support is limited to the installed Go TLS implementation. These controls do not
add pure ML-KEM groups, ML-DSA certificate authentication or unsupported protocols.

Tests cover classical/hybrid TLS 1.3 profiles, numeric destination pinning,
hostname validation, single-connection trust failure, public certificate evidence,
rejection without silent group fallback, invalid options and cancellation.
