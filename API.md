# Public names

The public API is the one of DESIGN 2.1; this file lists it, and the extras that are visible although they are not part of
it. The library is one module (`opcua`): helper functions that are not API are `@private` (visible inside the module only).
C3 cannot make a *method* private, so the internal methods of `Machine`, `ChunkReader` and `ChunkWriter` are public but are not API.

## API (DESIGN 2.1)

| Layer | Names |
|---|---|
| Faults | `faultdef` in `fault.c3` |
| Data | `NodeId`, `ExpandedNodeId`, `QualifiedName`, `LocalizedText`, `ExtensionObject`, `DiagnosticInfo`, `Variant` (`Scalar`, `ArrayData`, `BuiltIn`), `DataValue`, `StatusCode`, `UaDateTime`, `Guid`, `is_null`, `null_string`, `empty_string`, `bytes_is_null`, `null_bytes`, `empty_bytes`, the generated service structs and enums (`gen_types.c3`) |
| Codec | `ByteBuf`, `Limits`, `default_limits`, `Encoder`, `encoder`, `encoder_sizer`, `Decoder`, `decoder` and their `put_*` / `get_*` methods (the generated ones in `gen_codec.c3`), `variant_*`, `nodeid_num`, `nodeid_str`, `nodeid_equals`, `nodeid_hash`, `parse_nodeid`, `nodeid_to_string`, `datetime_from_unix_ms`, `datetime_to_unix_ms`, `index_range_valid`, `status_is_good/uncertain/bad`, `status_name`, the `*_ENCODING_ID` and `ATTRIBUTE_*` constants (`gen_ids.c3`) |
| Chunks | `MessageHeader`, `HelloMessage`, `AckMessage`, `ErrorMessage`, `ReverseHello`, `Message`, `ChunkReader` (`init`, `free`, `feed`, `next`, `mid_frame`), `ChunkWriter`, `chunk_writer` (`write_message`, `write_open`), `encode_hello`, `decode_hello`, `encode_ack`, `decode_ack`, `encode_error`, `decode_error`, `encode_reverse_hello`, `decode_reverse_hello`, `decode_header`, `MsgType`, `ChunkType`, `NodeIdKind` |
| Sans-IO core | `Machine`, `Config`, `default_config`, `Now`, `State`, `Identity`, `identity_anonymous`, `identity_username`, `Event`, `EventKind`, `Response`, `ResponseKind`, `Machine.init/free/connect/open_session/close/feed/transport_closed/pending_output/consume_output/next_deadline/handle_timeout/poll_event/send_*`, `write_value`, `find_endpoint`, `find_token_policy` |
| Blocking | `Client`, `client_connect`, `Client.open_session/close/free/service/next_deadline/get_endpoints/find_servers/find_servers_on_network/browse/translate/read/read_many/write/call`, `Client.last_status` |
| Transport | `Transport`, `TcpTransport`, `tcp_connect`, `EndpointUrl`, `parse_endpoint_url` |
| Security hook | `ChunkSecurity`, `SecurityNone`, `POLICY_*` |
| Diagnostics | `trace_chunk`, `FrameTracer` |
| Version | `version()` (reads `env::PROJECT_VERSION`, i.e. `project.json`) |

## Extras (public, documented, not part of the contract)

* `Machine.send_raw` and `PendingKind`: send a request whose body the caller encoded and get the undecoded answer (`ResponseKind.RAW`);
  used by the channel tests. `Machine.request_size_limit`, `Machine.queue_encoded`: internal, used by the services.
* `Client.browse_next`, `Client.release_point`, `Client.pump`, `Client.flush`, `Client.begin_call`, `Client.wait_for`,
  `Client.wait_response`, `Client.note`, `Client.mirror_status`: the pieces of the blocking loop (`browse_next` is useful on its own).
* `clock_now` (the adapter clock), `wait_socket` is `@private`.
* `extobj_body_decoder`: decode the body of a known ExtensionObject structure.
* `msg_type_name`, `service_name` is private, `known_response_id` is private; `MAX_ENDPOINT_URL`, `MIN_BUFFER_SIZE`, `SEQ_WRAP_LIMIT`, `MSG_OVERHEAD`,
  `STATUS_BAD_TIMEOUT`, `STATUS_BAD_CONNECTION_CLOSED`, `STATUS_BAD_OUT_OF_MEMORY`, `PUBLISH_RESPONSE_ENCODING_ID`, `SERVER_STATE_NODE_ID`,
  `DEFAULT_*` / `MIN_*` lifetime constants: protocol constants of the implementation.
* Internal methods that cannot be private: `Machine.on_*`, `Machine.queue_*`, `Machine.complete_*`, `Machine.find_pending`,
  `Machine.remove_pending`, `Machine.run_timers`, `Machine.fail`, `Machine.finish_close`, `Machine.begin_channel_close`,
  `Machine.alloc_*`, `Machine.is_late`, `Machine.is_renew_id`, `Machine.check_token`, `Machine.dispatch_response`,
  `ChunkReader.process`, `ChunkReader.add_chunk`, `ChunkReader.take_partial`, `ChunkReader.next_message`, `ChunkReader.release`,
  `ChunkWriter.write_chunks`, `Decoder.enter/leave`, `Encoder.enter/leave`, `ByteBuf.reserve`.
* Small public helpers of the codec: `guid_equals`, `utf8_valid`, `utf8_sanitize`, `Variant.count`, `new_slice` (macro), `MAX_ENCODE_DEPTH`,
  `UA_UNIX_EPOCH_*`, `UA_TICKS_PER_MS`.
* Public types that are internal: `PartialMessage` (the reassembly table of `ChunkReader`), `PendingRequest` (the request table of
  `Machine`).
* `tests` only: everything under `src/test`.

Review of the list: `c3_lookup` over the repository root against DESIGN 2.1; the names above that are not in 2.1 are the extras.
