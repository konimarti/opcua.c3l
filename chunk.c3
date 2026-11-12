module opcua;

// Transport messages and chunking (OPC 10000-6 7.1 and 6.7). Pure byte handling: no sockets, no clocks.

enum MsgType : char { HEL, ACK, ERR, OPN, MSG, CLO, RHE }
enum ChunkType : char { INTERMEDIATE, FINAL, ABORT }   // 'C', 'F', 'A'

const uint MIN_BUFFER_SIZE = 8192;          // 7.1.2.3: buffers below this are refused by the handshake
const uint MAX_ENDPOINT_URL = 4096;         // 7.1.2.3
const uint MSG_OVERHEAD = 24;               // 8 header + 4 channel + 4 token + 8 sequence header (MSG/CLO under None)
const uint SEQ_WRAP_LIMIT = 4294966271;     // UInt32.max - 1024 (6.7.2.4)
const uint SEQ_RESTART_BELOW = 1024;

struct MessageHeader
{
	MsgType type;
	ChunkType chunk;
	uint size;           // whole chunk, incl. the 8 header bytes
}

struct HelloMessage        // 7.1.2.3
{
	uint protocol_version;
	uint receive_buffer_size;
	uint send_buffer_size;
	uint max_message_size;
	uint max_chunk_count;
	String endpoint_url;
}

struct AckMessage          // 7.1.2.4
{
	uint protocol_version;
	uint receive_buffer_size;
	uint send_buffer_size;
	uint max_message_size;
	uint max_chunk_count;
}

struct ErrorMessage        // 7.1.2.5
{
	StatusCode error;
	String reason;
}

struct ReverseHello        // 7.1.2.6 (codec only in v1)
{
	String server_uri;
	String endpoint_url;
}

// ---------- message header ----------
fn String msg_type_name(MsgType t)
{
	switch (t)
	{
		case HEL: return "HEL";
		case ACK: return "ACK";
		case ERR: return "ERR";
		case OPN: return "OPN";
		case MSG: return "MSG";
		case CLO: return "CLO";
		case RHE: return "RHE";
	}
}

fn MsgType? msg_type_of(char a, char b, char c) @local
{
	if (a == 'H' && b == 'E' && c == 'L') return MsgType.HEL;
	if (a == 'A' && b == 'C' && c == 'K') return MsgType.ACK;
	if (a == 'E' && b == 'R' && c == 'R') return MsgType.ERR;
	if (a == 'O' && b == 'P' && c == 'N') return MsgType.OPN;
	if (a == 'M' && b == 'S' && c == 'G') return MsgType.MSG;
	if (a == 'C' && b == 'L' && c == 'O') return MsgType.CLO;
	if (a == 'R' && b == 'H' && c == 'E') return MsgType.RHE;
	return BAD_MESSAGE_TYPE~;
}

fn ChunkType? chunk_type_of(char c) @local
{
	switch (c)
	{
		case 'C': return ChunkType.INTERMEDIATE;
		case 'F': return ChunkType.FINAL;
		case 'A': return ChunkType.ABORT;
		default: return BAD_CHUNK~;
	}
}

fn char chunk_type_char(ChunkType c) @local
{
	switch (c)
	{
		case INTERMEDIATE: return 'C';
		case FINAL: return 'F';
		case ABORT: return 'A';
	}
}

fn uint load_u32(char[] b, sz at) @local => (uint)b[at] | (uint)b[at + 1] << 8 | (uint)b[at + 2] << 16 | (uint)b[at + 3] << 24;

// Eight bytes: type, chunk type, size. Only MSG and CLO may be split (C) or aborted (A); all other types are single frames.
// The size is returned as read: the limits are the reader's business.
fn MessageHeader? decode_header(char[] eight_bytes)
{
	if (eight_bytes.len < 8) return TRUNCATED~;
	MsgType t = msg_type_of(eight_bytes[0], eight_bytes[1], eight_bytes[2])!;
	ChunkType c = chunk_type_of(eight_bytes[3])!;
	if (c != ChunkType.FINAL && t != MsgType.MSG && t != MsgType.CLO) return BAD_CHUNK~;
	return { t, c, load_u32(eight_bytes, 4) };
}

// ---------- HEL / ACK / ERR / RHE ----------
fn void? begin_frame(ByteBuf* out, MsgType t, ChunkType c) @local
{
	Encoder e = encoder(out);
	e.put_raw((char[])msg_type_name(t))!;
	e.put_u8(chunk_type_char(c))!;
	e.put_u32(0)!;
}

fn void? end_frame(ByteBuf* out, sz start) @local => out.patch_u32(start + 4, (uint)(out.len - start));

fn void? encode_hello(ByteBuf* out, HelloMessage* m)
{
	if (m.endpoint_url.len > MAX_ENDPOINT_URL) return URL_INVALID~;
	sz start = out.len;
	defer catch out.len = start;
	begin_frame(out, MsgType.HEL, ChunkType.FINAL)!;
	Encoder e = encoder(out);
	e.put_u32(m.protocol_version)!;
	e.put_u32(m.receive_buffer_size)!;
	e.put_u32(m.send_buffer_size)!;
	e.put_u32(m.max_message_size)!;
	e.put_u32(m.max_chunk_count)!;
	e.put_string(m.endpoint_url)!;
	end_frame(out, start)!;
}

// Server side and tests. Body of a HEL frame (after the 8 header bytes).
fn HelloMessage? decode_hello(char[] body, Allocator allocator)
{
	if (body.len < 24) return TRUNCATED~;
	Decoder d = decoder(body, allocator);
	HelloMessage m;
	m.protocol_version = d.get_u32()!;
	m.receive_buffer_size = d.get_u32()!;
	m.send_buffer_size = d.get_u32()!;
	m.max_message_size = d.get_u32()!;
	m.max_chunk_count = d.get_u32()!;
	uint raw = d.get_u32()!;
	if (raw != 0xFFFF_FFFF && raw > MAX_ENDPOINT_URL) return URL_INVALID~;
	d.pos -= 4;
	m.endpoint_url = d.get_string()!;
	return m;
}

fn void? encode_ack(ByteBuf* out, AckMessage* m)
{
	sz start = out.len;
	defer catch out.len = start;
	begin_frame(out, MsgType.ACK, ChunkType.FINAL)!;
	Encoder e = encoder(out);
	e.put_u32(m.protocol_version)!;
	e.put_u32(m.receive_buffer_size)!;
	e.put_u32(m.send_buffer_size)!;
	e.put_u32(m.max_message_size)!;
	e.put_u32(m.max_chunk_count)!;
	end_frame(out, start)!;
}

// Body of an ACK frame. Fewer than 20 bytes is TRUNCATED; bytes after the five fields are ignored. The checks against
// the handshake rules (buffer sizes, version) belong to the state machine.
fn AckMessage? decode_ack(char[] body)
{
	if (body.len < 20) return TRUNCATED~;
	Decoder d = decoder(body, tmem);
	AckMessage m;
	m.protocol_version = d.get_u32()!;
	m.receive_buffer_size = d.get_u32()!;
	m.send_buffer_size = d.get_u32()!;
	m.max_message_size = d.get_u32()!;
	m.max_chunk_count = d.get_u32()!;
	return m;
}

fn void? encode_error(ByteBuf* out, ErrorMessage* m)
{
	sz start = out.len;
	defer catch out.len = start;
	begin_frame(out, MsgType.ERR, ChunkType.FINAL)!;
	Encoder e = encoder(out);
	e.put_u32((uint)m.error)!;
	e.put_string(m.reason)!;
	end_frame(out, start)!;
}

fn ErrorMessage? decode_error(char[] body, Allocator allocator)
{
	Decoder d = decoder(body, allocator);
	ErrorMessage m;
	m.error = (StatusCode)d.get_u32()!;
	m.reason = d.get_string()!;
	return m;
}

fn void? encode_reverse_hello(ByteBuf* out, ReverseHello* m)
{
	if (m.endpoint_url.len > MAX_ENDPOINT_URL) return URL_INVALID~;
	sz start = out.len;
	defer catch out.len = start;
	begin_frame(out, MsgType.RHE, ChunkType.FINAL)!;
	Encoder e = encoder(out);
	e.put_string(m.server_uri)!;
	e.put_string(m.endpoint_url)!;
	end_frame(out, start)!;
}

fn ReverseHello? decode_reverse_hello(char[] body, Allocator allocator)
{
	Decoder d = decoder(body, allocator);
	ReverseHello m;
	m.server_uri = d.get_string()!;
	m.endpoint_url = d.get_string()!;
	return m;
}

// ---------- reassembled messages ----------
// One reassembled message (all chunks of one RequestId joined), or an abort notice. HEL/ACK/ERR/RHE come back with
// the frame body (after the 8 header bytes) in `body`; feed it to the decode_* functions above.
struct Message
{
	MsgType type;
	uint channel_id;
	uint token_id;           // from the symmetric header (MSG/CLO)
	uint request_id;         // from the sequence header
	char[] body;             // service NodeId + service body (decrypted, unpadded); null when aborted
	bool aborted;            // an 'A' chunk: NOT a fault, the channel stays usable
	StatusCode abort_status;
	String abort_reason;     // points into the reader's buffer until the next call
	// OPN only: asymmetric header fields (point into the reader's buffer until the next call)
	String policy_uri;
	char[] sender_certificate;
	char[] receiver_thumbprint;
}

struct PartialMessage
{
	uint request_id;
	MsgType type;
	ByteBuf data;
	uint chunks;
}

fn sz sec_max_body(ChunkSecurity s, sz total, sz header_len, bool asymmetric) @local
{
	if (s == null) return total > header_len ? total - header_len : 0;
	return s.max_body(total, header_len, asymmetric);
}

fn sz sec_footer_len(ChunkSecurity s, sz body_len) @local => s == null ? 0 : s.footer_len(body_len);

fn char[]? sec_unprotect(ChunkSecurity s, char[] chunk, sz header_len, bool asymmetric) @local
{
	if (s == null)
	{
		if (header_len > chunk.len) return BAD_CHUNK~;
		return chunk[header_len..];
	}
	return s.unprotect(chunk, header_len, asymmetric);
}

// A String/ByteString read as a view into the input (no copy), with the codec's length checks.
fn char[]? get_view(Decoder* d, uint max) @local
{
	int len = d.get_length(max)!;
	if (len == -1) return null_bytes();
	return d.take((sz)len);
}

// Incremental splitter: feed arbitrary byte slices, pull whole messages. Reassembly is keyed by RequestId so chunks of
// different requests may interleave; bounded by Limits.max_pending_messages, Limits.max_chunk_count,
// Limits.max_message_size and Limits.max_reassembly_bytes (all partial messages together).
// A fault means stream corruption: the reader refuses further use (BAD_STATE). An abort chunk is a result, not a fault.
// `Message.body` and the other views stay valid until the next call of feed or next.
struct ChunkReader
{
	Allocator allocator;
	Limits limits;
	uint max_chunk_size;           // our announced ReceiveBufferSize
	ChunkSecurity security;        // null = SecurityNone
	ByteBuf pending;               // raw bytes not yet forming a frame
	sz pos;                        // consumed prefix of pending
	sz release_len;                // frame returned by the last next(), dropped on the next call
	ByteBuf held;                  // body of the last multi-chunk message
	PartialMessage[] partials;     // grown on demand up to limits.max_pending_messages
	sz partial_count;
	sz partial_bytes;              // body bytes held by all partials together
	uint last_sequence;
	bool have_sequence;
	bool broken;
}

fn void ChunkReader.init(&self, Allocator allocator, Limits limits, uint max_chunk_size, ChunkSecurity security = null)
{
	*self = {};
	self.allocator = allocator;
	self.limits = limits;
	self.max_chunk_size = max_chunk_size;
	self.security = security;
	self.pending.init(allocator, 4096);
	self.held.init(allocator, 64);
}

fn void ChunkReader.free(&self)
{
	for (sz i = 0; i < self.partial_count; i++) self.partials[i].data.free();
	if (self.partials.ptr != null) alloc::free(self.allocator, self.partials.ptr);
	self.partials = {};
	self.partial_count = 0;
	self.partial_bytes = 0;
	self.pending.free();
	self.held.free();
}

fn void ChunkReader.release(&self)
{
	self.pos += self.release_len;
	self.release_len = 0;
	self.held.clear();
}

fn void? ChunkReader.feed(&self, char[] data)
{
	self.release();
	if (self.pos > 0)
	{
		sz rest = self.pending.len - self.pos;
		if (rest > 0) mem::move(self.pending.data.ptr, self.pending.data.ptr + self.pos, rest);
		self.pending.len = rest;
		self.pos = 0;
	}
	self.pending.append(data)!;
}

// Buffered bytes of an unfinished frame or message (a clean end of stream has none).
fn bool ChunkReader.mid_frame(&self) => self.pending.len - self.pos - self.release_len > 0 || self.partial_count > 0;

// true + *out when a message is complete (or aborted); false when more bytes are needed.
fn bool? ChunkReader.next(&self, Message* out)
{
	if (self.broken) return BAD_STATE~;
	bool? r = self.next_message(out);
	if (catch err = r)
	{
		self.broken = true;
		return err~;
	}
	return r;
}

fn sz min_frame_size(MsgType t) @local
{
	switch (t)
	{
		case MSG:
		case CLO: return MSG_OVERHEAD;
		case OPN: return 32;     // 12 + three length fields + sequence header
		default: return 8;
	}
}

fn bool? ChunkReader.next_message(&self, Message* out)
{
	self.release();
	while (true)
	{
		char[] view = self.pending.data[self.pos:self.pending.len - self.pos];
		// reject garbage as early as the bytes allow
		if (view.len >= 3) msg_type_of(view[0], view[1], view[2])!;
		if (view.len >= 4) chunk_type_of(view[3])!;
		if (view.len < 8) return false;
		MessageHeader h = decode_header(view[:8])!;
		if (h.size < 8 || h.size > self.max_chunk_size || h.size < min_frame_size(h.type)) return BAD_CHUNK~;
		if (view.len < h.size) return false;
		char[] frame = view[:h.size];
		self.release_len = h.size;
		if (self.process(frame, h, out)!) return true;
		self.pos += h.size;
		self.release_len = 0;
	}
}

fn bool sequence_follows(uint last, uint seq) @local
{
	if (seq == last + 1) return true;
	return last >= SEQ_WRAP_LIMIT && seq < SEQ_RESTART_BELOW;
}

fn sz ChunkReader.find_partial(&self, uint request_id)
{
	for (sz i = 0; i < self.partial_count; i++)
	{
		if (self.partials[i].request_id == request_id) return i;
	}
	return -1;
}

fn void ChunkReader.drop_partial(&self, sz idx)
{
	self.partial_bytes -= self.partials[idx].data.len;
	self.partials[idx].data.free();
	self.partial_count--;
	if (idx != self.partial_count) self.partials[idx] = self.partials[self.partial_count];
}

fn PartialMessage*? ChunkReader.new_partial(&self, uint request_id, MsgType type)
{
	if (self.partial_count >= self.limits.max_pending_messages) return TOO_MANY_PENDING~;
	if (self.partial_count == self.partials.len)
	{
		sz cap = self.partials.len == 0 ? 4 : self.partials.len * 2;
		if (cap > self.limits.max_pending_messages) cap = self.limits.max_pending_messages;
		PartialMessage[] fresh = alloc::alloc_array_try(self.allocator, PartialMessage, cap)!;
		for (sz i = 0; i < self.partial_count; i++) fresh[i] = self.partials[i];
		if (self.partials.ptr != null) alloc::free(self.allocator, self.partials.ptr);
		self.partials = fresh;
	}
	PartialMessage* p = &self.partials[self.partial_count];
	*p = { .request_id = request_id, .type = type };
	p.data.init(self.allocator, 256);
	self.partial_count++;
	return p;
}

// Parses one whole frame. true = *out is filled; false = intermediate chunk stored, nothing to return yet.
fn bool? ChunkReader.process(&self, char[] frame, MessageHeader h, Message* out)
{
	*out = { .type = h.type };
	switch (h.type)
	{
		case HEL:
		case ACK:
		case ERR:
		case RHE:
			out.body = frame[8..];
			return true;
		default:
	}
	bool asym = h.type == MsgType.OPN;
	out.channel_id = load_u32(frame, 8);
	sz header_len;
	if (asym)
	{
		Decoder d = decoder(frame, self.allocator, self.limits);
		d.pos = 12;
		out.policy_uri = (String)get_view(&d, self.limits.max_string_length)!;
		out.sender_certificate = get_view(&d, self.limits.max_bytestring_length)!;
		out.receiver_thumbprint = get_view(&d, self.limits.max_bytestring_length)!;
		header_len = d.pos;
	}
	else
	{
		out.token_id = load_u32(frame, 12);
		header_len = 16;
	}
	char[] plain = sec_unprotect(self.security, frame, header_len, asym)!;
	if (plain.len < 8) return BAD_CHUNK~;
	uint seq = load_u32(plain, 0);
	out.request_id = load_u32(plain, 4);
	char[] body = plain[8..];
	if (self.have_sequence && !sequence_follows(self.last_sequence, seq)) return SEQUENCE_ERROR~;
	self.last_sequence = seq;
	self.have_sequence = true;
	sz found = self.find_partial(out.request_id);
	switch (h.chunk)
	{
		case ABORT:
			if (found >= 0) self.drop_partial(found);
			Decoder d = decoder(body, self.allocator, self.limits);
			out.aborted = true;
			out.abort_status = (StatusCode)d.get_u32()!;
			out.abort_reason = (String)get_view(&d, self.limits.max_string_length)!;
			out.body = {};
			return true;
		case FINAL:
			if (found < 0)
			{
				if (body.len > self.limits.max_message_size) return MESSAGE_TOO_LARGE~;
				out.body = body;
				return true;
			}
			PartialMessage* p = &self.partials[found];
			if (p.type != h.type) return BAD_CHUNK~;
			self.add_chunk(p, body)!;
			out.body = self.take_partial(found);
			return true;
		case INTERMEDIATE:
			PartialMessage* p;
			if (found >= 0)
			{
				p = &self.partials[found];
				if (p.type != h.type) return BAD_CHUNK~;
			}
			else
			{
				p = self.new_partial(out.request_id, h.type)!;
			}
			self.add_chunk(p, body)!;
			return false;
	}
}

fn void? ChunkReader.add_chunk(&self, PartialMessage* p, char[] body)
{
	if (p.chunks + 1 > self.limits.max_chunk_count) return TOO_MANY_CHUNKS~;
	if (body.len > self.limits.max_message_size || p.data.len + body.len > self.limits.max_message_size) return MESSAGE_TOO_LARGE~;
	if (self.partial_bytes + body.len > self.limits.max_reassembly_bytes) return MESSAGE_TOO_LARGE~;
	p.data.append(body)!;
	p.chunks++;
	self.partial_bytes += body.len;
}

// Moves the finished message out of the partial table into `held` (valid until the next call).
fn char[] ChunkReader.take_partial(&self, sz idx)
{
	PartialMessage* p = &self.partials[idx];
	self.held.free();
	self.held = p.data;
	p.data = {};
	self.partial_bytes -= self.held.len;
	self.partial_count--;
	if (idx != self.partial_count) self.partials[idx] = self.partials[self.partial_count];
	return self.held.bytes();
}

// ---------- writer ----------
struct ChunkWriter
{
	uint max_chunk_size;     // min(our send buffer, peer ReceiveBufferSize from ACK)
	uint max_chunk_count;    // 0 = unlimited (peer value)
	uint max_message_size;   // peer MaxMessageSize, 0 = unlimited
	uint next_sequence;      // continues across renewals (per channel direction)
	ChunkSecurity security;  // null = SecurityNone
}

fn ChunkWriter chunk_writer(uint max_chunk_size, ChunkSecurity security = null)
{
	return { .max_chunk_size = max_chunk_size, .next_sequence = 1, .security = security };
}

// MSG / CLO (symmetric header). TOO_MANY_CHUNKS / MESSAGE_TOO_LARGE before any byte is queued.
fn void? ChunkWriter.write_message(&self, ByteBuf* out, MsgType type, uint channel_id, uint token_id, uint request_id, char[] body)
{
	if (type != MsgType.MSG && type != MsgType.CLO) return BAD_STATE~;
	return self.write_chunks(out, type, channel_id, token_id, request_id, body);
}

// OPN (asymmetric header: policy URI, sender certificate, thumbprint come from `security`; None gives the URI and two
// null ByteStrings).
fn void? ChunkWriter.write_open(&self, ByteBuf* out, uint channel_id, uint request_id, char[] body)
{
	return self.write_chunks(out, MsgType.OPN, channel_id, 0, request_id, body);
}

fn void? ChunkWriter.write_chunks(&self, ByteBuf* out, MsgType type, uint channel_id, uint token_id, uint request_id, char[] body)
{
	bool asym = type == MsgType.OPN;
	ByteBuf tail;                       // bytes after the channel id: token, or the asymmetric header
	tail.init(out.allocator, 128);
	defer tail.free();
	Encoder te = encoder(&tail);
	if (asym)
	{
		te.put_string(self.security == null ? POLICY_NONE : self.security.policy_uri())!;
		te.put_bytestring(self.security == null ? null_bytes() : self.security.sender_certificate())!;
		te.put_bytestring(self.security == null ? null_bytes() : self.security.receiver_thumbprint())!;
	}
	else
	{
		te.put_u32(token_id)!;
	}
	sz header_len = 8 + 4 + tail.len;   // in front of the sequence header
	sz per = sec_max_body(self.security, self.max_chunk_size, header_len + 8, asym);
	if (per == 0) return BAD_CHUNK~;
	sz count = body.len == 0 ? 1 : (body.len + per - 1) / per;
	if (self.max_chunk_count != 0 && count > self.max_chunk_count) return TOO_MANY_CHUNKS~;
	if (self.max_message_size != 0 && body.len > self.max_message_size) return MESSAGE_TOO_LARGE~;

	sz start = out.len;
	defer catch out.len = start;
	ByteBuf chunk;
	chunk.init(out.allocator, header_len + 8 + per + 64);
	defer chunk.free();
	uint seq = self.next_sequence;
	sz offset = 0;
	for (sz i = 0; i < count; i++)
	{
		sz n = body.len - offset < per ? body.len - offset : per;
		char[] piece = body[offset:n];
		sz size = header_len + 8 + n + sec_footer_len(self.security, n);
		chunk.clear();
		Encoder e = encoder(&chunk);
		e.put_raw((char[])msg_type_name(type))!;
		e.put_u8(chunk_type_char(i + 1 == count ? ChunkType.FINAL : ChunkType.INTERMEDIATE))!;
		e.put_u32((uint)size)!;
		e.put_u32(channel_id)!;
		e.put_raw(tail.bytes())!;
		e.put_u32(seq)!;
		e.put_u32(request_id)!;
		e.put_raw(piece)!;
		if (self.security != null) self.security.protect(&chunk, header_len, asym)!;
		if (chunk.len != size || size > self.max_chunk_size) return BAD_CHUNK~;
		out.append(chunk.bytes())!;
		offset += n;
		seq = seq > SEQ_WRAP_LIMIT ? 1 : seq + 1;
	}
	self.next_sequence = seq;
}
