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

## Peer behaviour
* Not observed yet: no peer was available when this was written. `peer_idle_without_service` prints an `OBSERVED:` line for the
  outcome of a read after an idle period longer than the channel lifetime without `service()`; copy that result here after the
  first run against the open62541 example server.
* The channel renewal request carries no AuthenticationToken even when a session exists (found by a scripted test, to be
  confirmed against a server).
