# ADR 0049. Mobile Admin Surfaces over the Same Bridge (§4.8-7)

> Status: Accepted (2026-09-26)

## Context

Mobile administration must use the same runtime contract as desktop and must not create a second definition of administrator authority. Some administrative actions have irreversible effects and require confirmation designed for those actions.

The bridge also carries JSON payloads and collection grant data. Manual JSON construction risks malformed or injected payloads, and fetching data already present in a response adds unnecessary round-trips.

## Decision

Mobile administrator surfaces use the shared one-parser bridge. The client recognizes administrator access from a collection row with `access:"admin"`, matching the desktop's server-derived marker.

Where JSON construction remains manual, escape backslashes before quotes. Prefer structural JSON construction over string interpolation. Parse each collection's inline grants from one response and derive both collection and grant views from that response.

Keep destructive member controls (reset, remove, transfer), the Space flip, and collection create, rename, and delete on desktop until dedicated mobile confirmation flows exist.

## Consequences

Mobile and desktop use the same administrator signal and payload parser. Expiry days are converted using the phone clock; the daemon refuses a past expiry. The join-queue `secret_ok` warning remains advisory: a false value requires out-of-band verification and does not refuse the request.

## References

- Original record D46.
- Thin mobile bridge: ADR 0048.
