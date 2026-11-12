# Quirks and observations

## Transport
* TCP_NODELAY: `std::net::SocketOption` has no such member (REUSEADDR, REUSEPORT, KEEPALIVE, BROADCAST, OOBINLINE, DONTROUTE),
  so it is not set. Every chunk is written with one send call (the Machine hands over whole chunks), which avoids the small-write
  stall the option guards against. Re-check when std exposes it.
* `Socket.write` is `send(..., 0)`: no MSG_NOSIGNAL. Applications must ignore SIGPIPE (README).
* `poll_ms` reports an interrupted wait as an error; `wait_socket` looks again up to four times before it calls the connection
  closed. Not exercised by a test (needs a signal).
* A read that returns 0 bytes is the peer's orderly shutdown (`CLOSED`); the adapter then calls `Machine.transport_closed`, which
  reports `TRANSPORT_TRUNCATED` when it happens in the middle of a frame.

## Client nonce
* The 32 byte client nonce is taken from `random::entropy()` as it is (`Config.nonce_entropy`); `nonce_seed` (a splitmix64
  generator) is only the fallback for a config without entropy. Under policy None the nonce is unused; a signing policy must keep
  the entropy path.

## open62541 v1.5.10 (built without encryption)
* ci_server (anonymous, port as given on the command line, default 4840): one endpoint, mode None / policy None, user token
  policy `anonymous` only. Test nodes: `ns=1;s=the.answer` (Int32, writable), the method `ns=1;i=62541` ("hello world", one String
  in, one String out) under the Objects folder; there is no Add method and no Double / String / array node.
* Browsing the Objects folder (i=85) returns the HasTypeDefinition reference (FolderType i=61) first, then Server i=2253 and the
  application nodes. It is a normal reference in the result, not an error.
* The server revises the requested channel lifetime of 3 600 000 ms to 600 000 ms; a requested 4 000 ms is kept (4 000 ms).
  The first sequence number it sends is 1, its channel ids are small integers that grow per connection.
* access_control_server: the None endpoint offers the user token policy `username` only (no anonymous policy), so an anonymous
  session is refused locally with `BAD_STATE`. Credentials peter / peter123 (found in the binary's strings); the cleartext opt-in
  is needed and the server logs "Processing an unencrypted UserToken". A wrong password gives the ServiceResult
  `BadUserAccessDenied` on ActivateSession, which the client reports as `SERVICE_FAULT` with that status.
* Reading an unknown node (i=999999) returns a DataValue with `BadNodeIdUnknown` (data, not a fault).

## Idle behaviour (observed with ci_server, requested lifetime 4 000 ms)
* With `service()` called every 100 ms for the revised lifetime plus one second: one renewal, no renew failure, and the read after
  it succeeds.
* Without `service()`: after sleeping the revised lifetime plus one second the next read fails at once with `TIMEOUT`: the
  call starts with `handle_timeout`, the renewal is due but the old token's lifetime has already passed, so the machine fails
  (`TIMEOUT`) instead of sending a request the server would drop. Recorded line:
  `OBSERVED: read after an idle period without service() failed with opcua::TIMEOUT`.

## Client
* The channel renewal request carries no AuthenticationToken even when a session exists (confirmed: the server accepts the
  renewals in the idle test).
