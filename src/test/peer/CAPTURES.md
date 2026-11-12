# First request layouts (redacted trace)

No peer was available, so these lines come from the redacted trace of the exact bytes the machine writes (the same frames the
unit tests compare byte for byte with the hand-laid-out vectors B4 and B7). To refresh them from a real run:
`uatool read opc.tcp://127.0.0.1:4840 i=2259 --verbose` prints the same format on stderr (`>` outgoing, `<` incoming).

```
> HEL F size=56 body=48 bytes
< ACK F size=28 body=20 bytes
> OPN F size=132 channel=0 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1 type=i=446 (OpenSecureChannelRequest) auth=<redacted> body=49 bytes
> MSG F size=93 channel=7 token=2 seq=5 request=4 type=i=631 (ReadRequest) auth=<redacted> body=65 bytes
```

## Comparison by hand

* OPN request: 132 bytes = 8 header + 4 channel id + 4 + 47 policy URI + 4 + 4 null ByteStrings + 8 sequence and request id + 53 body
  (type id `01 00 BE 01`, 29 byte RequestHeader, protocol version, Issue, None, null nonce, 3 600 000 ms). Matches vector B4 and
  10000-6 6.7.2.3 (asymmetric header) / 10000-4 5.5.2.2 (OpenSecureChannel request parameters). No discrepancy found.
* Read request: 93 bytes = 24 header bytes (8 + channel + token + sequence header) + 69 service bytes (type id 631, RequestHeader
  with the session token `ns0;i=10000`, MaxAge, TimestampsToReturn, one ReadValueId). Matches vector B7 and 10000-4 5.10.2.
  No discrepancy found; the encoding of the header's AdditionalHeader as the three bytes `00 00 00` follows 10000-6 5.2.2.15.
