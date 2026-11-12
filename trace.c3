module opcua;

// Redacted trace dump: the only dump facility (uatool --verbose and the peer tests use nothing else). It prints transport
// and chunk headers, service type ids and sizes. The AuthenticationToken of a request, the UserNameIdentityToken and the
// whole ActivateSession body are replaced by "<redacted>", and the bytes of a message body are never printed.

fn String service_name(uint id)
{
	switch (id)
	{
		case SERVICE_FAULT_ENCODING_ID: return "ServiceFault";
		case OPEN_SECURE_CHANNEL_REQUEST_ENCODING_ID: return "OpenSecureChannelRequest";
		case OPEN_SECURE_CHANNEL_RESPONSE_ENCODING_ID: return "OpenSecureChannelResponse";
		case CLOSE_SECURE_CHANNEL_REQUEST_ENCODING_ID: return "CloseSecureChannelRequest";
		case CREATE_SESSION_REQUEST_ENCODING_ID: return "CreateSessionRequest";
		case CREATE_SESSION_RESPONSE_ENCODING_ID: return "CreateSessionResponse";
		case ACTIVATE_SESSION_REQUEST_ENCODING_ID: return "ActivateSessionRequest";
		case ACTIVATE_SESSION_RESPONSE_ENCODING_ID: return "ActivateSessionResponse";
		case CLOSE_SESSION_REQUEST_ENCODING_ID: return "CloseSessionRequest";
		case CLOSE_SESSION_RESPONSE_ENCODING_ID: return "CloseSessionResponse";
		case GET_ENDPOINTS_REQUEST_ENCODING_ID: return "GetEndpointsRequest";
		case GET_ENDPOINTS_RESPONSE_ENCODING_ID: return "GetEndpointsResponse";
		case FIND_SERVERS_REQUEST_ENCODING_ID: return "FindServersRequest";
		case FIND_SERVERS_RESPONSE_ENCODING_ID: return "FindServersResponse";
		case FIND_SERVERS_ON_NETWORK_REQUEST_ENCODING_ID: return "FindServersOnNetworkRequest";
		case FIND_SERVERS_ON_NETWORK_RESPONSE_ENCODING_ID: return "FindServersOnNetworkResponse";
		case BROWSE_REQUEST_ENCODING_ID: return "BrowseRequest";
		case BROWSE_RESPONSE_ENCODING_ID: return "BrowseResponse";
		case BROWSE_NEXT_REQUEST_ENCODING_ID: return "BrowseNextRequest";
		case BROWSE_NEXT_RESPONSE_ENCODING_ID: return "BrowseNextResponse";
		case TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_REQUEST_ENCODING_ID: return "TranslateBrowsePathsToNodeIdsRequest";
		case TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_RESPONSE_ENCODING_ID: return "TranslateBrowsePathsToNodeIdsResponse";
		case READ_REQUEST_ENCODING_ID: return "ReadRequest";
		case READ_RESPONSE_ENCODING_ID: return "ReadResponse";
		case WRITE_REQUEST_ENCODING_ID: return "WriteRequest";
		case WRITE_RESPONSE_ENCODING_ID: return "WriteResponse";
		case CALL_REQUEST_ENCODING_ID: return "CallRequest";
		case CALL_RESPONSE_ENCODING_ID: return "CallResponse";
		case PUBLISH_RESPONSE_ENCODING_ID: return "PublishResponse";
		default: return "";
	}
}

fn uint trace_u32(char[] b, sz at) @private => (uint)b[at] | (uint)b[at + 1] << 8 | (uint)b[at + 2] << 16 | (uint)b[at + 3] << 24;

// Describes the service in the sequence-header-and-body part `rest` (type id first) of a MSG, CLO or OPN chunk.
fn void trace_service(DString* s, char[] rest) @private
{
	if (rest.len == 0)
	{
		s.append(" body=0 bytes");
		return;
	}
	@pool()
	{
		Decoder d = decoder(rest, tmem);
		NodeId tid = d.get_nodeid() ?? nodeid_num(0, 0);
		uint id = (tid.kind == NodeIdKind.NUMERIC && tid.ns == 0) ? tid.num : 0;
		if (id == 0)
		{
			s.appendf(" type=<unknown> body=%d bytes", rest.len);
			return;
		}
		String name = service_name(id);
		s.appendf(" type=i=%d", id);
		if (name.len > 0) s.appendf(" (%s)", name);
		if (id == ACTIVATE_SESSION_REQUEST_ENCODING_ID || id == USER_NAME_IDENTITY_TOKEN_ENCODING_ID)
		{
			s.append(" body=<redacted>");
			return;
		}
		if (!known_response_id(id)) s.append(" auth=<redacted>");
		s.appendf(" body=%d bytes", rest.len - d.pos);
	};
}

// One chunk (or transport frame) as one line of text appended to `out_text`.
fn void trace_chunk(char[] chunk, ByteBuf* out_text)
{
	DString s = dstring::temp();
	trace_chunk_text(&s, chunk);
	s.append("\n");
	(void)out_text.append((char[])s.str_view());
}

fn void trace_chunk_text(DString* s, char[] chunk) @private
{
	if (chunk.len < 8)
	{
		s.appendf("<short chunk, %d bytes>", chunk.len);
		return;
	}
	MessageHeader? hr = decode_header(chunk[:8]);
	if (catch err = hr)
	{
		s.appendf("<bad header, %d bytes>", chunk.len);
		return;
	}
	MessageHeader h = hr;
	char kind = h.chunk == ChunkType.FINAL ? 'F' : (h.chunk == ChunkType.INTERMEDIATE ? 'C' : 'A');
	s.appendf("%s %c size=%d", msg_type_name(h.type), kind, h.size);
	switch (h.type)
	{
		case MSG:
		case CLO:
			if (chunk.len < 24)
			{
				s.append(" <short>");
				return;
			}
			s.appendf(" channel=%d token=%d seq=%d request=%d", trace_u32(chunk, 8), trace_u32(chunk, 12), trace_u32(chunk, 16), trace_u32(chunk, 20));
			if (h.chunk == ChunkType.ABORT)
			{
				s.append(" aborted");
				return;
			}
			if (h.chunk == ChunkType.FINAL)
			{
				trace_service(s, chunk[24..]);
			}
			else
			{
				s.appendf(" body=%d bytes", chunk.len - 24);
			}
		case OPN:
			if (chunk.len < 12)
			{
				s.append(" <short>");
				return;
			}
			s.appendf(" channel=%d", trace_u32(chunk, 8));
			@pool()
			{
				Decoder d = decoder(chunk, tmem);
				d.pos = 12;
				String policy = d.get_string() ?? "";
				char[] cert = d.get_bytestring() ?? null_bytes();
				char[] thumb = d.get_bytestring() ?? null_bytes();
				s.appendf(" policy=%s sender_certificate=%d bytes thumbprint=%d bytes", policy, cert.len, thumb.len);
				if (d.remaining() >= 8)
				{
					s.appendf(" seq=%d request=%d", trace_u32(chunk, d.pos), trace_u32(chunk, d.pos + 4));
					trace_service(s, chunk[d.pos + 8..]);
				}
			};
		default:
			s.appendf(" body=%d bytes", chunk.len - 8);
	}
}

// Splits a byte stream into frames and traces every complete one.
struct FrameTracer
{
	ByteBuf pending;
}

fn void FrameTracer.init(&self, Allocator allocator) => self.pending.init(allocator, 256);
fn void FrameTracer.free(&self) => self.pending.free();

fn void FrameTracer.feed(&self, char[] data, ByteBuf* out_text)
{
	if (catch self.pending.append(data)) return;
	while (self.pending.len >= 8)
	{
		char[] all = self.pending.bytes();
		uint size = trace_u32(all, 4);
		if (size < 8 || size > 1 << 24)
		{
			self.pending.clear();                      // not a frame boundary: give up on this buffer
			return;
		}
		if (self.pending.len < size) return;
		trace_chunk(all[:size], out_text);
		sz rest = self.pending.len - size;
		if (rest > 0) mem::move(all.ptr, all.ptr + size, rest);
		self.pending.len = rest;
	}
}
