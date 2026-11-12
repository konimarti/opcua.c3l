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

## asyncua 2.1.0 (peers/asyncua_server.py, SecurityPolicy None, anonymous and user name peter / peter123)
* ACK: ReceiveBufferSize and SendBufferSize **65535** (open62541: 65536), MaxMessageSize 104 857 600, MaxChunkCount 1601. The
  machine accepts both (the minimum is 8192).
* OPN: the first sequence number is 1, the lifetime requested (3 600 000 ms) is kept; open62541 revises it to 600 000 ms. A
  requested 4 000 ms is kept by both.
* CreateSession announces `MaxRequestMessageSize` 65536 but accepts much larger requests (a 100 000 element Int32 array write of
  about 400 KB in chunks of 8192 bytes succeeds). The machine applies the announced limit by default (`MESSAGE_TOO_LARGE`);
  `Config.ignore_server_request_limit` switches that off and the multi-chunk peer test uses it.
* The user name token policy names the None security policy (`SecurityPolicyUri` = `#None`); the password still travels in
  clear text. The machine accepts that with `allow_cleartext_password` (found by this peer; before, any non-empty policy URI was
  refused). open62541 leaves the field empty.
* GetEndpoints: the endpoint URL is the one that was asked for (`localhost` stays `localhost`), but a request with a path the
  server does not know (`/wrong/path`) is answered with the configured URL `opc.tcp://127.0.0.1:4841/`. The client never reconnects
  to the host in an answer (it only returns the endpoints), so both are harmless. open62541 echoes the requested URL.
* A wrong endpoint path in the HEL is accepted by both servers.
* BrowseNext with an invalid continuation point is answered with a ServiceFault `BadUserAccessDenied` (asyncua's permission
  rules do not list BrowseNext; its own client gets the same). open62541 answers per result with `BadContinuationPointInvalid`
  (data). The peer test accepts both and records which one it saw.
* Browse ignores `RequestedMaxReferencesPerNode`: all references come in the first answer, so continuation points are only
  exercised with open62541.
* The Add method checks its argument count with a Python TypeError (a call with one argument is answered with a Bad status).

## Renewal (both peers, requested lifetime 4 000 ms)
* Ten seconds with `service()`: 3 renewals, 0 renew failures, every read good.
* Peer stopped (SIGSTOP) at 2 800 ms and continued at 3 700 ms: 2 `CHANNEL_RENEW_FAILED` events, then the renewal is answered and
  the channel recovers (1 renewal at about 3 700 ms, before the old token's end at 4 000 ms). The request timeout was 300 ms.

## Skips
* `peer_multichunk_array` is skipped against open62541's ci_server: it has no array node (reason printed:
  `SKIP: no OPCUA_NODE_ARRAY configured`). `peer_call_wrong_argument_types` is skipped when the method takes a String (open62541).
  Against asyncua nothing is skipped.

## Client
* The channel renewal request carries no AuthenticationToken even when a session exists (confirmed: the server accepts the
  renewals in the idle test).
