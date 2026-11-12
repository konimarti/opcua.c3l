module opcua;

// Error model: DESIGN.md section 6. Faults are grouped by prefix. Numeric detail: Machine.last_status / Client.last_status.
faultdef
	// --- codec (OPC 10000-6 5.2) ---
	TRUNCATED,           // input ends inside a value
	BUFFER_FULL,         // fixed output buffer too small (sizer/limits)
	BAD_LENGTH,          // negative/oversized length, array too large (limits), dimension mismatch
	BAD_ENCODING,        // unknown encoding mask/bits, bad UTF-8, bad variant type id, reserved bits
	BAD_NODEID,          // NodeId encoding byte unknown / flag bits in a plain NodeId
	DEPTH_EXCEEDED,      // recursion limit (Variant/DiagnosticInfo/ExtensionObject nesting)
	UNKNOWN_TYPE,        // ExtensionObject body type not known (only when Decoder.strict_types)
	// --- chunks / transport framing (OPC 10000-6 6.7, 7.1) ---
	BAD_MESSAGE_TYPE,    // header MessageType not one of HEL ACK ERR OPN MSG CLO RHE
	BAD_CHUNK,           // chunk size outside [minimum, receive buffer], bad chunk type, mixed MsgType in one message
	BAD_HANDSHAKE,       // ACK/OPN-response violates the handshake rules (buffer < 8192, bad version, policy mismatch, channel id 0)
	MESSAGE_TOO_LARGE,   // reassembled/outgoing message above a limit (local, ACK, MaxRequestMessageSize)
	TOO_MANY_CHUNKS,     // > max_chunk_count
	TOO_MANY_PAGES,      // Client.browse hit Limits.max_browse_pages
	TOO_MANY_REFERENCES, // Client.browse hit Limits.max_browse_references or max_browse_bytes
	TOO_MANY_PENDING,    // more partial messages / outstanding requests than the limits allow
	PEER_ERROR,          // ERR message received; status in last_status
	// --- secure channel ---
	CHANNEL_CLOSED,
	CHANNEL_ID_MISMATCH,
	TOKEN_UNKNOWN,       // unknown TokenId
	SECURITY_UNSUPPORTED, // policy or mode not implemented / password would travel in clear
	SEQUENCE_ERROR,      // SequenceNumber not consecutive (6.7.2.4)
	REQUEST_ID_UNKNOWN,  // response for unknown RequestId that is not a known late reply
	// --- service level ---
	SERVICE_FAULT,       // ServiceFault received or Bad ServiceResult; status in last_status
	BAD_STATUS,          // a convenience call found a Bad per-node status it cannot return as data
	BAD_RESPONSE,        // framed but wrong: wrong type id, handle mismatch, result count mismatch, trailing bytes
	SESSION_LOST,        // BadSessionIdInvalid / BadSessionClosed / BadSessionNotActivated: reconnect needed
	NOT_CONNECTED,
	BAD_STATE,           // API called in the wrong state
	EMPTY_REQUEST,       // request with zero nodes/items (servers answer BadNothingToDo): refused locally
	TIMEOUT,             // handshake/request/renewal deadline passed (Machine.handle_timeout) or transport read/write timeout; same name in every library
	WRITE_NOT_ALLOWED,   // Write or Call refused: Config.allow_write is false (Call can change state, so it is covered too)
	// --- transport ---
	CLOSED,              // peer closed the connection cleanly (between frames); same name in every library's faultdef
	TRANSPORT_TRUNCATED, // connection closed in the middle of a frame
	URL_INVALID;         // bad opc.tcp:// URL (scheme, port, host, length > 4096)
