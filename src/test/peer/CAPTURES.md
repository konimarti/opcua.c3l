# Captured exchanges (open62541 v1.5.10 ci_server, SecurityPolicy None)

Real runs of `uatool ... --verbose` against the open62541 example server (`>` outgoing, `<` incoming; AuthenticationToken,
tokens and ActivateSession bodies are redacted by the trace, no message body is printed). The server side of both exchanges is
also stored byte for byte in `src/test/real_server_fixtures.c3` and replayed by `real_server_test.c3` without a peer.

## `uatool endpoints opc.tcp://127.0.0.1:4840 --verbose`

```
> HEL F size=56 body=48 bytes
< ACK F size=28 body=20 bytes
> OPN F size=132 channel=0 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1 type=i=446 (OpenSecureChannelRequest) auth=<redacted> body=49 bytes
< OPN F size=135 channel=2 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1 type=i=449 (OpenSecureChannelResponse) body=52 bytes
> MSG F size=93 channel=2 token=2 seq=2 request=2 type=i=428 (GetEndpointsRequest) auth=<redacted> body=65 bytes
< MSG F size=457 channel=2 token=2 seq=2 request=2 type=i=431 (GetEndpointsResponse) body=429 bytes
endpoint opc.tcp://127.0.0.1:4840 mode=None policy=http://opcfoundation.org/UA/SecurityPolicy#None tokens=anonymous
> CLO F size=57 channel=2 token=2 seq=3 request=3 type=i=452 (CloseSecureChannelRequest) auth=<redacted> body=29 bytes
```

## `uatool read opc.tcp://127.0.0.1:4840 i=2259 --verbose`

```
> HEL F size=56 body=48 bytes
< ACK F size=28 body=20 bytes
> OPN F size=132 channel=0 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1 type=i=446 (OpenSecureChannelRequest) auth=<redacted> body=49 bytes
< OPN F size=135 channel=1 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1 type=i=449 (OpenSecureChannelResponse) body=52 bytes
> MSG F size=240 channel=1 token=1 seq=2 request=2 type=i=461 (CreateSessionRequest) auth=<redacted> body=212 bytes
< MSG F size=559 channel=1 token=1 seq=2 request=2 type=i=464 (CreateSessionResponse) body=531 bytes
> MSG F size=147 channel=1 token=1 seq=3 request=3 type=i=467 (ActivateSessionRequest) body=<redacted>
< MSG F size=96 channel=1 token=1 seq=3 request=3 type=i=470 (ActivateSessionResponse) body=68 bytes
> MSG F size=108 channel=1 token=1 seq=4 request=4 type=i=631 (ReadRequest) auth=<redacted> body=80 bytes
< MSG F size=66 channel=1 token=1 seq=4 request=4 type=i=634 (ReadResponse) body=38 bytes
i=2259 Good 0
> MSG F size=75 channel=1 token=1 seq=5 request=5 type=i=473 (CloseSessionRequest) auth=<redacted> body=47 bytes
< MSG F size=52 channel=1 token=1 seq=5 request=5 type=i=476 (CloseSessionResponse) body=24 bytes
> CLO F size=74 channel=1 token=1 seq=6 request=6 type=i=452 (CloseSecureChannelRequest) auth=<redacted> body=46 bytes
```

## Comparison with the specification and the vectors

* HEL: 56 bytes, equals vector B1 except for the URL. The ACK carries 65536 / 65536 byte buffers and a MaxMessageSize / chunk
  count of its own (10000-6 7.1.2.4); the machine accepts it.
* OPN request: 132 bytes (vector B4). The response is 135 bytes: the same asymmetric header (policy None, two null ByteStrings),
  sequence number 1 and request id 1 (the first received sequence number is free, T5, but this server starts at 1), type id 449.
  The server **revised the requested lifetime of 3 600 000 ms to 600 000 ms**.
* GetEndpoints request: 93 bytes, equals vector B10 in size and layout; the response lists one endpoint (None / None, token
  policy anonymous).
* Read request: the ReadRequest layout equals vector B7 apart from the node, the token and the handles; the response decodes to
  an Int32 DataValue with status Good.
* No discrepancy between the design document, the vectors and the real server was found.
