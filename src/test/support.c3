module opcua;

// Shared helpers of the unit tests (all test allocations come from the temp allocator, which the test driver resets).

fn int test_hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// "4D 53 47" or "4d5347" -> bytes; anything that is not a hex digit (spaces, newlines) is skipped.
fn char[] unhex(String s)
{
	char[] out = alloc::alloc_array(tmem, char, s.len / 2 + 1);
	sz n = 0;
	int hi = -1;
	foreach (c : (char[])s)
	{
		int d = test_hex_digit(c);
		if (d < 0) continue;
		if (hi < 0)
		{
			hi = d;
		}
		else
		{
			out[n] = (char)(hi * 16 + d);
			n++;
			hi = -1;
		}
	}
	return out[:n];
}

fn Decoder dec(String hex) => decoder(unhex(hex), tmem);

// The built-in kinds the codec handles, for the generic sweeps.
enum Kind
{
	BOOL, U16, U32, U64, F32, F64, STRING, BYTES, GUID, NODEID,
	DATETIME, QNAME, LTEXT, XNODEID, EXTOBJ, DIAG, VARIANT, DATAVALUE,
}

// Decodes one value of kind `k` and encodes it again into `e` (a sizer or a buffer encoder).
fn void? roundtrip(Decoder* d, Encoder* e, Kind k)
{
	switch (k)
	{
		case BOOL: e.put_bool(d.get_bool()!)!;
		case U16: e.put_u16(d.get_u16()!)!;
		case U32: e.put_u32(d.get_u32()!)!;
		case U64: e.put_u64(d.get_u64()!)!;
		case F32: e.put_f32(d.get_f32()!)!;
		case F64: e.put_f64(d.get_f64()!)!;
		case STRING: e.put_string(d.get_string()!)!;
		case BYTES: e.put_bytestring(d.get_bytestring()!)!;
		case GUID: e.put_guid(d.get_guid()!)!;
		case NODEID: e.put_nodeid(d.get_nodeid()!)!;
		case DATETIME: e.put_datetime(d.get_datetime()!)!;
		case QNAME: e.put_qualified_name(d.get_qualified_name()!)!;
		case LTEXT: e.put_localized_text(d.get_localized_text()!)!;
		case XNODEID: e.put_expanded_nodeid(d.get_expanded_nodeid()!)!;
		case EXTOBJ: e.put_extension_object(d.get_extension_object()!)!;
		case DIAG: e.put_diagnostic_info(d.get_diagnostic_info()!)!;
		case VARIANT: e.put_variant(d.get_variant()!)!;
		case DATAVALUE: e.put_data_value(d.get_data_value()!)!;
	}
}

// Decoding, followed by re-encoding the decoded value into a sizer (so the encoders are exercised too).
fn void? decode_kind(Decoder* d, Kind k)
{
	Encoder sink = encoder_sizer();
	return roundtrip(d, &sink, k);
}

// encode(decode(hex)) as bytes
fn char[] reencode(String hex, Kind k)
{
	Decoder d = dec(hex);
	ByteBuf b;
	b.init(tmem);
	Encoder e = encoder(&b);
	roundtrip(&d, &e, k)!!;
	return b.bytes();
}

// size reported by the sizing encoder for the decoded value
fn sz sizer_of(String hex, Kind k)
{
	Decoder d = dec(hex);
	Encoder e = encoder_sizer();
	roundtrip(&d, &e, k)!!;
	return e.written;
}

// A valid vector: decodes and consumes all bytes, re-encodes to the same bytes (when canonical), the sizer agrees,
// and every proper prefix fails with TRUNCATED.
fn void check_vector(String hex, Kind k, bool canonical = true)
{
	assert(decodes_fully(hex, k), "vector must decode");
	char[] re = reencode(hex, k);
	if (canonical) assert(re == unhex(hex), "re-encoded bytes");
	assert(sizer_of(hex, k) == re.len, "sizer");
	prefix_sweep(hex, k);
}

// True when decoding `hex` as `k` fails with exactly `expected`.
fn bool fails_with(String hex, Kind k, fault expected)
{
	Decoder d = dec(hex);
	if (catch err = decode_kind(&d, k)) return err == expected;
	return false;
}

// Decodes `hex` as `k`; true when it succeeds and consumes every byte.
fn bool decodes_fully(String hex, Kind k)
{
	Decoder d = dec(hex);
	if (catch err = decode_kind(&d, k)) return false;
	return d.remaining() == 0;
}

// Every proper prefix of the valid vector must fail with TRUNCATED (and the whole vector must decode).
fn void prefix_sweep(String hex, Kind k)
{
	char[] full = unhex(hex);
	assert(decodes_fully(hex, k), "vector must decode");
	for (sz n = 0; n < full.len; n++)
	{
		Decoder d = decoder(full[:n], tmem);
		if (catch err = decode_kind(&d, k))
		{
			assert(err == TRUNCATED, "prefix must fail with TRUNCATED");
		}
		else
		{
			unreachable("a proper prefix decoded");
		}
	}
}

// encoder output of one value
fn char[] enc_u16(ushort v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_u16(v)!!; return b.bytes(); }
fn char[] enc_u32(uint v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_u32(v)!!; return b.bytes(); }
fn char[] enc_u64(ulong v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_u64(v)!!; return b.bytes(); }
fn char[] enc_f32(float v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_f32(v)!!; return b.bytes(); }
fn char[] enc_f64(double v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_f64(v)!!; return b.bytes(); }
fn char[] enc_bool(bool v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_bool(v)!!; return b.bytes(); }
fn char[] enc_string(String v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_string(v)!!; return b.bytes(); }
fn char[] enc_bytes(char[] v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_bytestring(v)!!; return b.bytes(); }
fn char[] enc_guid(Guid v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_guid(v)!!; return b.bytes(); }
fn char[] enc_nodeid(NodeId v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_nodeid(v)!!; return b.bytes(); }

// Size reported by the sizing encoder for a NodeId / String (encoded_size == len(encode)).
fn sz size_nodeid(NodeId v) { Encoder e = encoder_sizer(); e.put_nodeid(v)!!; return e.written; }
fn sz size_string(String v) { Encoder e = encoder_sizer(); e.put_string(v)!!; return e.written; }

// Small deterministic PRNG for the mutation tests (xorshift64).
struct Rng { ulong state; }
fn ulong Rng.next(&self)
{
	ulong x = self.state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	self.state = x;
	return x;
}

// True when the expression faults with exactly `expected` (a missing fault is a failed assertion at the call site).
macro bool @ok(#expr)
{
	if (catch #expr) return false;
	return true;
}

macro bool @fails(#expr, fault expected)
{
	if (catch err = #expr) return err == expected;
	return false;
}

fn char[] enc_variant(Variant v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_variant(v)!!; return b.bytes(); }
fn char[] enc_dv(DataValue v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_data_value(v)!!; return b.bytes(); }
fn char[] enc_ltext(LocalizedText v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_localized_text(v)!!; return b.bytes(); }
fn char[] enc_qname(QualifiedName v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_qualified_name(v)!!; return b.bytes(); }
fn char[] enc_xnode(ExpandedNodeId v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_expanded_nodeid(v)!!; return b.bytes(); }
fn char[] enc_ext(ExtensionObject v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_extension_object(v)!!; return b.bytes(); }
fn char[] enc_diag(DiagnosticInfo v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_diagnostic_info(v)!!; return b.bytes(); }
fn char[] enc_datetime(UaDateTime v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_datetime(v)!!; return b.bytes(); }

// "AA BB CC" text of a byte slice (for the vector helpers that take hex)
fn String tohex(char[] bytes)
{
	DString s = dstring::temp();
	foreach (i, c : bytes)
	{
		if (i > 0) s.append_char(' ');
		s.appendf("%02X", c);
	}
	return s.str_view();
}

// slice of two values
macro pair($Type, a, b)
{
	$Type[] s = alloc::alloc_array(tmem, $Type, 2);
	s[0] = ($Type)a;
	s[1] = ($Type)b;
	return s;
}
