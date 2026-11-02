# ADR 0007. Single-String Protobuf Gateway

> Status: Accepted

## Context

Front-end tiers need a uniform interface to `baluard-core` that supports development without native builds. Desktop, CLI, browser extension, and mobile all reach the vault engine, and the interface must stay stable as routes are added without regenerating bindings for each new capability.

## Decision

All layers will communicate through a unified serialized gateway using `HandleRequest(action, payload)`. The input is one Protobuf-serialized string containing the action and its parameters. The output is a serialized response string. Front-end tiers can set `MOCK_BACKEND=true` to skip native builds and provide hardcoded mock Protobuf payloads directly to UI components.

**Wire shape (`proto/auth.proto`).** `GatewayRequest` carries four string fields: `action`, `payload`, `session_token`, and `slug`. `GatewayResponse` carries `success`, `error_message`, `payload`, and `session_token`. The payload is a JSON document inside the Protobuf string, so adding a route or a field changes no schema and regenerates no bindings. The `slug` field routes a request to one open vault, and an empty slug means the active vault. The session token is returned on unlock and must accompany every later request for that vault. Host-level routes that must work before a token exists, such as listing vaults for the login screen, are not token-gated. Everything else is gated, with a constant-time token comparison (ADR 0008).

**Framing.** Messages ride Unix domain sockets as length-delimited frames: a varint length prefix followed by the Protobuf message. The daemon rejects a frame larger than 4 MiB, answers with an error, and closes the connection rather than draining the body. The desktop bridge refuses responses of 5 MiB or more. The browser native-messaging host relays between the extension's JSON and the daemon's Protobuf frames, and it enforces its own smaller bounds: 64 KiB per request and 1 MiB per response, the latter being the browser's host-to-extension hard cap (ADR 0024).

**Schemas.** `proto/auth.proto` defines the gateway envelope and is the only schema on the wire. `proto/vault.proto` is a reference schema for the entry model (`VaultEntry`, `CipherType`, `LoginUri`, `UriMatchStrategy`); the wire format carries tagged JSON in `payload` instead. The daemon compiles both files through `prost-build`, and the CLI compiles `auth.proto` only.

**Scope.** The gateway serves the desktop UI, the CLI, and the browser extension relay, all through the daemon socket. The mobile client does not use it: it hosts the runtime in-process and calls typed UniFFI methods (ADR 0010).

**Mock backend.** The mock-backend switch is a design intent. No front-end tier in the repository reads `MOCK_BACKEND`, so UI development currently needs a running daemon.

## Consequences

The gateway decouples client development from native builds in principle and removes per-route binding churn. Because the payload is untyped JSON inside a string, the schema compiler cannot check route payloads, so payload shape is enforced by the daemon handlers and by client tests. Every action string is part of the trust surface: desktop and bridge clients are restricted to allowlists (ADR 0008, ADR 0024). The Protobuf wire protocol is implemented over Unix sockets. Windows has a named-pipe path reserved but no transport yet (ADR 0008). The route table in `crates/baluard-daemon/src/handler.rs` is the authoritative list; it has grown well beyond the thirty routes recorded when this decision was made.

## References

- `proto/auth.proto`, `proto/vault.proto`
- `crates/baluard-daemon/src/handler.rs`
- `crates/baluard-nmh/src/main.rs`
- ADR 0008, ADR 0024
