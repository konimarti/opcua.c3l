module opcua;

// ---------- growable output buffer ----------
// Own small type instead of std::io::ByteBuffer / List{char}: it needs patch_u32 (chunk size back-patching), a stable
// view (bytes()), an explicit Allocator and a counting mode for the sizer. The size type is `sz` everywhere (as in std 0.8.6).
struct ByteBuf
{
	Allocator allocator;
	char[] data;      // capacity
	sz len;
	sz min_cap;
}

fn void ByteBuf.init(&self, Allocator allocator, sz initial = 256)
{
	self.allocator = allocator;
	self.data = {};
	self.len = 0;
	self.min_cap = initial;
}

fn void ByteBuf.free(&self)
{
	if (self.data.ptr != null) alloc::free(self.allocator, self.data.ptr);
	self.data = {};
	self.len = 0;
}

fn void ByteBuf.clear(&self) => self.len = 0;
fn char[] ByteBuf.bytes(&self) => self.data[:self.len];

fn void? ByteBuf.reserve(&self, sz extra)
{
	sz need = self.len + extra;
	if (need < self.len) return BUFFER_FULL~;
	if (need <= self.data.len) return;
	sz cap = self.data.len * 2;
	if (cap < need) cap = need;
	if (cap < self.min_cap) cap = self.min_cap;
	char[] fresh = alloc::alloc_array_try(self.allocator, char, cap)!;
	if (self.len > 0) mem::copy(fresh.ptr, self.data.ptr, self.len);
	if (self.data.ptr != null) alloc::free(self.allocator, self.data.ptr);
	self.data = fresh;
}

fn void? ByteBuf.append(&self, char[] bytes)
{
	if (bytes.len == 0) return;
	self.reserve(bytes.len)!;
	mem::copy(self.data.ptr + self.len, bytes.ptr, bytes.len);
	self.len += bytes.len;
}

// Overwrites 4 already written bytes at `pos` (little endian).
fn void? ByteBuf.patch_u32(&self, sz pos, uint value)
{
	if (pos < 0 || self.len < 4 || pos > self.len - 4) return BUFFER_FULL~;
	self.data[pos] = (char)value;
	self.data[pos + 1] = (char)(value >> 8);
	self.data[pos + 2] = (char)(value >> 16);
	self.data[pos + 3] = (char)(value >> 24);
}

// ---------- limits (DoS protection) ----------
// The primary bound is always "declared length * smallest element size <= remaining input"; these are the hard ceilings.
struct Limits
{
	uint max_string_length;       // default 1 MiB (String, XmlElement)
	uint max_bytestring_length;   // default 16 MiB (ByteString, certificates, continuation points)
	uint max_array_length;        // default 1_000_000 elements
	uint max_matrix_elements;     // default 1_000_000 (overflow-checked product)
	uint max_depth;               // default 32 (Variant/DiagnosticInfo/ExtensionObject nesting; spec allows up to 100)
	uint max_message_size;        // default 16 MiB (reassembled message)
	uint max_chunk_count;         // default 64 (local ceiling even if the peer announces 0 = unlimited)
	uint max_pending_messages;    // default 16 (partially reassembled messages, keyed by RequestId)
	uint max_reassembly_bytes;    // default = max_message_size: total bytes held by ALL partial messages together
	uint max_outstanding_requests; // default 64
	uint max_browse_pages;        // default 1000: BrowseNext rounds of one Client.browse
	uint max_browse_references;   // default 1_000_000: references merged by one Client.browse
	uint max_browse_bytes;        // default 256 MiB: bytes of the merged references (100 each plus their names)
}

fn Limits default_limits() => { 1 << 20, 16 << 20, 1_000_000, 1_000_000, 32, 16 << 20, 64, 16, 16 << 20, 64, 1000, 1_000_000, 256 << 20 };

// ---------- Encoder (OPC 10000-6 5.2, little endian) ----------
struct Encoder
{
	ByteBuf* out;       // null in sizing mode
	sz written;         // bytes produced (also in sizing mode)
	uint depth;
}

fn Encoder encoder(ByteBuf* out) => { .out = out };
fn Encoder encoder_sizer() => { .out = null };            // counts bytes only: encoded_size(x) property tests

fn void? Encoder.put_raw(&self, char[] b)
{
	if (self.out != null) self.out.append(b)!;
	self.written += b.len;
}

fn void? Encoder.put_bool(&self, bool v) => self.put_u8(v ? 1 : 0);

fn void? Encoder.put_u8(&self, char v)
{
	char[1] b = { v };
	self.put_raw(&b)!;
}

fn void? Encoder.put_u16(&self, ushort v)
{
	char[2] b = { (char)v, (char)(v >> 8) };
	self.put_raw(&b)!;
}

fn void? Encoder.put_u32(&self, uint v)
{
	char[4] b = { (char)v, (char)(v >> 8), (char)(v >> 16), (char)(v >> 24) };
	self.put_raw(&b)!;
}

fn void? Encoder.put_u64(&self, ulong v)
{
	char[8] b;
	for (int i = 0; i < 8; i++) b[i] = (char)(v >> (i * 8));
	self.put_raw(&b)!;
}

fn void? Encoder.put_f32(&self, float v) => self.put_u32(bitcast(v, uint));     // NaN payloads are copied bit for bit
fn void? Encoder.put_f64(&self, double v) => self.put_u64(bitcast(v, ulong));

// String / ByteString / XmlElement: Int32 length, -1 = null (is_null), 0 = empty (5.2.2.4, 5.2.2.7, 5.2.2.8)
fn void? Encoder.put_bytestring(&self, char[] v)
{
	if (v.ptr == null)
	{
		return self.put_u32(0xFFFF_FFFF);
	}
	if (v.len > int::max) return BAD_LENGTH~;
	self.put_u32((uint)v.len)!;
	self.put_raw(v)!;
}

fn void? Encoder.put_string(&self, String v) => self.put_bytestring((char[])v);

fn void? Encoder.put_guid(&self, Guid v)
{
	self.put_u32(v.d1)!;
	self.put_u16(v.d2)!;
	self.put_u16(v.d3)!;
	self.put_raw(&v.d4)!;
}

// NodeId (5.2.2.9): the smallest of TwoByte (0x00), FourByte (0x01), Numeric (0x02) for numeric ids.
fn void? Encoder.put_nodeid(&self, NodeId v) => self.put_nodeid_flagged(v, 0);

// Same, with the ExpandedNodeId flag bits (0x80 NamespaceUri, 0x40 ServerIndex) or-ed into the encoding byte.
fn void? Encoder.put_nodeid_flagged(&self, NodeId v, char flags)
{
	switch (v.kind)
	{
		case NUMERIC:
			if (v.ns == 0 && v.num <= 255)
			{
				self.put_u8(0x00 | flags)!;
				self.put_u8((char)v.num)!;
			}
			else if (v.ns <= 255 && v.num <= 65535)
			{
				self.put_u8(0x01 | flags)!;
				self.put_u8((char)v.ns)!;
				self.put_u16((ushort)v.num)!;
			}
			else
			{
				self.put_u8(0x02 | flags)!;
				self.put_u16(v.ns)!;
				self.put_u32(v.num)!;
			}
		case STRING:
			self.put_u8(0x03 | flags)!;
			self.put_u16(v.ns)!;
			self.put_string(v.str)!;
		case GUID:
			self.put_u8(0x04 | flags)!;
			self.put_u16(v.ns)!;
			self.put_guid(v.guid)!;
		case OPAQUE:
			self.put_u8(0x05 | flags)!;
			self.put_u16(v.ns)!;
			self.put_bytestring(v.bytes)!;
	}
}

// Array helper used by generated code: Int32 length, then the elements.
fn void? Encoder.put_array_len(&self, sz n, bool null_array = false)
{
	if (null_array) return self.put_u32(0xFFFF_FFFF);
	if (n < 0 || n > int::max) return BAD_LENGTH~;
	return self.put_u32((uint)n);
}

// ---------- Decoder ----------
struct Decoder
{
	char[] input;
	sz pos;
	Allocator allocator;      // every decoded String/array/pointer is allocated here
	Limits limits;
	uint depth;
	bool strict_types;        // UNKNOWN_TYPE for unknown ExtensionObject type ids
	bool validate_utf8;       // default true: invalid UTF-8 -> BAD_ENCODING; false: invalid bytes become U+FFFD
}

fn Decoder decoder(char[] input, Allocator allocator, Limits limits = default_limits()) => { .input = input, .allocator = allocator, .limits = limits, .validate_utf8 = true };
fn sz Decoder.remaining(&self) => self.input.len - self.pos;

// Recursion guard for Variant / DataValue / DiagnosticInfo nesting.
fn void? Decoder.enter(&self)
{
	if (self.depth >= self.limits.max_depth) return DEPTH_EXCEEDED~;
	self.depth++;
}

fn void Decoder.leave(&self) => self.depth--;

fn char[]? Decoder.take(&self, sz n)
{
	if (n < 0 || n > self.remaining()) return TRUNCATED~;
	char[] r = self.input[self.pos:n];
	self.pos += n;
	return r;
}

// Boolean: any non-zero byte is true; the encoder writes 0 or 1.
fn bool? Decoder.get_bool(&self) => self.get_u8()! != 0;

fn char? Decoder.get_u8(&self)
{
	char[] b = self.take(1)!;
	return b[0];
}

fn ushort? Decoder.get_u16(&self)
{
	char[] b = self.take(2)!;
	return (ushort)b[0] | (ushort)((ushort)b[1] << 8);
}

fn uint? Decoder.get_u32(&self)
{
	char[] b = self.take(4)!;
	return (uint)b[0] | ((uint)b[1] << 8) | ((uint)b[2] << 16) | ((uint)b[3] << 24);
}

fn ulong? Decoder.get_u64(&self)
{
	char[] b = self.take(8)!;
	ulong v;
	for (int i = 0; i < 8; i++) v |= (ulong)b[i] << (i * 8);
	return v;
}

fn float? Decoder.get_f32(&self) => bitcast(self.get_u32()!, float);
fn double? Decoder.get_f64(&self) => bitcast(self.get_u64()!, double);

// Reads an Int32 length for String / ByteString. Returns -1 for null. The check order keeps allocation behind every check.
fn int? Decoder.get_length(&self, uint max)
{
	int len = (int)self.get_u32()!;
	if (len == -1) return -1;
	if (len < -1) return BAD_LENGTH~;
	if ((uint)len > max) return BAD_LENGTH~;
	if ((sz)len > self.remaining()) return TRUNCATED~;
	return len;
}

fn char[]? Decoder.get_bytestring(&self)
{
	int len = self.get_length(self.limits.max_bytestring_length)!;
	if (len == -1) return null_bytes();
	if (len == 0) return empty_bytes();
	char[] raw = self.take((sz)len)!;
	char[] copy = alloc::alloc_array_try(self.allocator, char, (sz)len)!;
	mem::copy(copy.ptr, raw.ptr, (sz)len);
	return copy;
}

fn String? Decoder.get_string(&self)
{
	int len = self.get_length(self.limits.max_string_length)!;
	if (len == -1) return null_string();
	if (len == 0) return empty_string();
	char[] raw = self.take((sz)len)!;
	if (utf8_valid(raw))
	{
		char[] copy = alloc::alloc_array_try(self.allocator, char, (sz)len)!;
		mem::copy(copy.ptr, raw.ptr, (sz)len);
		return (String)copy;
	}
	if (self.validate_utf8) return BAD_ENCODING~;
	return utf8_sanitize(self.allocator, raw);
}

fn Guid? Decoder.get_guid(&self)
{
	Guid g;
	g.d1 = self.get_u32()!;
	g.d2 = self.get_u16()!;
	g.d3 = self.get_u16()!;
	char[] rest = self.take(8)!;
	mem::copy(&g.d4, rest.ptr, 8);
	return g;
}

// Accepts every valid encoding (also non-minimal ones such as a Numeric i=5). Flag bits 0x80/0x40 are only valid in an
// ExpandedNodeId and are BAD_NODEID here.
fn NodeId? Decoder.get_nodeid(&self)
{
	if (self.remaining() == 0) return TRUNCATED~;
	if ((self.input[self.pos] & 0xC0) != 0) return BAD_NODEID~;      // before anything is decoded or allocated
	char flags;
	return self.get_nodeid_flagged(&flags);
}

// Returns the ExpandedNodeId flag bits (0x80, 0x40) of the encoding byte in *flags.
fn NodeId? Decoder.get_nodeid_flagged(&self, char* flags)
{
	char enc = self.get_u8()!;
	*flags = enc & 0xC0;
	enc &= 0x3F;
	NodeId id;
	switch (enc)
	{
		case 0x00:
			id.kind = NUMERIC;
			id.num = self.get_u8()!;
		case 0x01:
			id.kind = NUMERIC;
			id.ns = self.get_u8()!;
			id.num = self.get_u16()!;
		case 0x02:
			id.kind = NUMERIC;
			id.ns = self.get_u16()!;
			id.num = self.get_u32()!;
		case 0x03:
			id.kind = STRING;
			id.ns = self.get_u16()!;
			id.str = self.get_string()!;
		case 0x04:
			id.kind = GUID;
			id.ns = self.get_u16()!;
			id.guid = self.get_guid()!;
		case 0x05:
			id.kind = OPAQUE;
			id.ns = self.get_u16()!;
			id.bytes = self.get_bytestring()!;
		default:
			return BAD_NODEID~;
	}
	return id;
}

// Array helper used by generated code. -1 = null array. Checks the limit and count * min_element_size <= remaining()
// (64-bit arithmetic) before anything is allocated.
fn int? Decoder.get_array_len(&self, sz min_element_size)
{
	int n = (int)self.get_u32()!;
	if (n == -1) return -1;
	if (n < -1) return BAD_LENGTH~;
	if ((uint)n > self.limits.max_array_length) return BAD_LENGTH~;
	// overflow-free form of n * min_element_size > remaining
	sz min_size = min_element_size < 1 ? 1 : min_element_size;
	if ((ulong)n > (ulong)self.remaining() / (ulong)min_size) return TRUNCATED~;
	return n;
}

// ---------- UTF-8 (strict: no overlong forms, no surrogates, at most U+10FFFF) ----------
fn bool is_cont(char b) @local => (b & 0xC0) == 0x80;

// Length of the valid UTF-8 sequence that starts at s[i], 0 if the bytes there are not valid.
fn sz utf8_seq_len(char[] s, sz i) @private
{
	char b0 = s[i];
	sz left = s.len - i;
	if (b0 < 0x80) return 1;
	if (b0 >= 0xC2 && b0 <= 0xDF)
	{
		return (left >= 2 && is_cont(s[i + 1])) ? 2 : 0;
	}
	if (b0 >= 0xE0 && b0 <= 0xEF)
	{
		if (left < 3 || !is_cont(s[i + 1]) || !is_cont(s[i + 2])) return 0;
		char b1 = s[i + 1];
		if (b0 == 0xE0 && b1 < 0xA0) return 0;
		if (b0 == 0xED && b1 > 0x9F) return 0;
		return 3;
	}
	if (b0 >= 0xF0 && b0 <= 0xF4)
	{
		if (left < 4 || !is_cont(s[i + 1]) || !is_cont(s[i + 2]) || !is_cont(s[i + 3])) return 0;
		char b1 = s[i + 1];
		if (b0 == 0xF0 && b1 < 0x90) return 0;
		if (b0 == 0xF4 && b1 > 0x8F) return 0;
		return 4;
	}
	return 0;
}

fn bool utf8_valid(char[] s)
{
	sz i = 0;
	while (i < s.len)
	{
		sz n = utf8_seq_len(s, i);
		if (n == 0) return false;
		i += n;
	}
	return true;
}

// Copy of `s` where every invalid byte is replaced by U+FFFD (EF BF BD).
fn String? utf8_sanitize(Allocator allocator, char[] s)
{
	sz out_len = 0;
	sz i = 0;
	while (i < s.len)
	{
		sz n = utf8_seq_len(s, i);
		if (n == 0) { out_len += 3; i += 1; }
		else { out_len += n; i += n; }
	}
	char[] out = alloc::alloc_array_try(allocator, char, out_len)!;
	sz o = 0;
	i = 0;
	while (i < s.len)
	{
		sz n = utf8_seq_len(s, i);
		if (n == 0)
		{
			out[o] = 0xEF;
			out[o + 1] = 0xBF;
			out[o + 2] = 0xBD;
			o += 3;
			i += 1;
		}
		else
		{
			mem::copy(out.ptr + o, s.ptr + i, n);
			o += n;
			i += n;
		}
	}
	return (String)out;
}
