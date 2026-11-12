# opcua.c3l

Pure C3 OPC UA client library (UA binary over opc.tcp, sans-IO core). Work in progress, version 0.1.0.

Status: the binary encoding of the built-in types (primitives, String, ByteString, Guid, NodeId) and the codec limits are in place;
chunking, secure channel, sessions and services follow. MIT licensed.

## Memory contract of the decoders

Every decoded value (strings, byte strings, arrays, structures with arrays) is allocated from the allocator you pass to the
decoder, and nothing is released when a decode fails half way: the children of the elements decoded so far stay allocated.
Pass an arena or the temporary allocator (for example a `DynamicArenaAllocator` per response) and free it as a whole.
The `Machine` follows the same rule: the allocator you give to a `send_*` call receives the decoded response.

## Using TcpTransport

`TcpTransport` writes with the standard library's `send`, which does not set `MSG_NOSIGNAL`: an application that writes to a
connection the peer has already closed must ignore `SIGPIPE` (or it is terminated by the signal on POSIX systems).
