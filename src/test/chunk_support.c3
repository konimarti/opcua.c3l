module opcua;

// Helpers and the exact byte vectors shared by the transport tests.

const String B1_HEL = "48 45 4C 46 38 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00 18 00 00 00 6F 70 63 2E 74 63 70 3A 2F 2F 6C 6F 63 61 6C 68 6F 73 74 3A 34 38 34 30";
const String B2_ACK = "41 43 4B 46 1C 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00 00 00";
const String B3_ERR = "45 52 52 46 11 00 00 00 00 00 80 80 01 00 00 00 78";
const String B7_HEAD = "4D 53 47 46 5D 00 00 00 07 00 00 00 02 00 00 00 05 00 00 00 04 00 00 00";
const String B7_BODY1 = "01 00 77 02 01 00 10 27 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 FF FF FF FF 88 13";
const String B7_BODY2 = "00 00 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 01 00 00 00 01 00 D2 08 0D 00 00 00 FF FF FF FF 00 00 FF FF FF FF";
const String B11_C1 = "4D 53 47 43 36 00 00 00 07 00 00 00 02 00 00 00 05 00 00 00 04 00 00 00";
const String B11_C2 = "4D 53 47 46 3F 00 00 00 07 00 00 00 02 00 00 00 06 00 00 00 04 00 00 00";
const String B12_ABORT = "4D 53 47 41 21 00 00 00 07 00 00 00 02 00 00 00 07 00 00 00 04 00 00 00 00 00 01 80 01 00 00 00 78";
const String RHE_FRAME = "52 48 45 46 12 00 00 00 01 00 00 00 75 01 00 00 00 65";
const String MSG_AABB = "4D 53 47 46 1A 00 00 00 07 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 AA BB";

fn char[] cat(char[] a, char[] b)
{
	char[] r = alloc::alloc_array(tmem, char, a.len + b.len);
	if (a.len > 0) mem::copy(r.ptr, a.ptr, a.len);
	if (b.len > 0) mem::copy(r.ptr + a.len, b.ptr, b.len);
	return r;
}

fn char[] b7_frame() => cat(unhex(B7_HEAD), cat(unhex(B7_BODY1), unhex(B7_BODY2)));
fn char[] b7_body() => cat(unhex(B7_BODY1), unhex(B7_BODY2));
fn char[] b11_chunk1() => cat(unhex(B11_C1), unhex(B7_BODY1));
fn char[] b11_chunk2() => cat(unhex(B11_C2), unhex(B7_BODY2));

// A MSG chunk (channel 7, token 2) with the given chunk type character, sequence number, request id and body.
fn char[] mk_chunk(char kind, uint seq, uint req, char[] body)
{
	ByteBuf b;
	b.init(tmem, 64);
	Encoder e = encoder(&b);
	e.put_raw((char[])"MSG")!!;
	e.put_u8(kind)!!;
	e.put_u32((uint)(24 + body.len))!!;
	e.put_u32(7)!!;
	e.put_u32(2)!!;
	e.put_u32(seq)!!;
	e.put_u32(req)!!;
	e.put_raw(body)!!;
	return b.bytes();
}

// An abort chunk (channel 7, token 2).
fn char[] mk_abort(uint seq, uint req, uint status, String reason)
{
	ByteBuf body;
	body.init(tmem, 32);
	Encoder e = encoder(&body);
	e.put_u32(status)!!;
	e.put_string(reason)!!;
	return mk_chunk('A', seq, req, body.bytes());
}

fn ChunkReader new_reader(uint max_chunk = 65536, Limits limits = default_limits())
{
	ChunkReader r;
	r.init(mem, limits, max_chunk);
	return r;
}

fn Message pull(ChunkReader* r)
{
	Message m;
	assert(r.next(&m)!!, "a message is expected");
	return m;
}

fn bool nothing_more(ChunkReader* r)
{
	Message m;
	return !r.next(&m)!!;
}

fn bool next_fails(ChunkReader* r, fault f)
{
	Message m;
	return @fails(r.next(&m), f);
}

// Feeds `hex`, then expects the reader to fail with `f`.
fn bool frame_fails(String hex, fault f, uint max_chunk = 65536)
{
	ChunkReader r = new_reader(max_chunk);
	defer r.free();
	r.feed(unhex(hex))!!;
	return next_fails(&r, f);
}

// Every message the reader yields for `data`, as (type, request id, body length) text; stops at the first fault.
fn String drain(ChunkReader* r)
{
	DString s = dstring::temp();
	Message m;
	while (try more = r.next(&m))
	{
		if (!more) break;
		s.appendf("%d:%d:%d;", (int)m.type.ordinal, m.request_id, m.body.len);
	}
	return s.str_view();
}

// A test double that adds a 4 byte footer to every chunk.
struct FooterSecurity (ChunkSecurity) { uint protects; uint unprotects; }
fn String FooterSecurity.policy_uri(&self) @dynamic => "urn:test:footer";
fn MessageSecurityMode FooterSecurity.mode(&self) @dynamic => MessageSecurityMode.SIGN;
fn sz FooterSecurity.footer_len(&self, sz body_len) @dynamic => 4;
fn sz FooterSecurity.max_body(&self, sz total, sz header_len, bool asymmetric) @dynamic => total - header_len - 4;
fn void? FooterSecurity.protect(&self, ByteBuf* chunk, sz header_len, bool asymmetric) @dynamic
{
	self.protects++;
	chunk.append((char[])"FOOT")!;
}
fn char[]? FooterSecurity.unprotect(&self, char[] chunk, sz header_len, bool asymmetric) @dynamic
{
	self.unprotects++;
	if (chunk.len < header_len + 4) return BAD_CHUNK~;
	if (chunk[chunk.len - 4:4] != (char[])"FOOT") return BAD_CHUNK~;
	return chunk[header_len..chunk.len - 5];
}
fn char[] FooterSecurity.sender_certificate(&self) @dynamic => (char[])"CERT";
fn char[] FooterSecurity.receiver_thumbprint(&self) @dynamic => null_bytes();
