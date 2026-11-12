module opcua;

// String, ByteString, Guid, null versus empty, UTF-8 (OPC 10000-6 5.2.2.4 - 5.2.2.8). Vectors V10-V15, V20, M40-M45, M78.

fn void fixtures_string() @test
{
	assert(enc_string("abc") == unhex("03 00 00 00 61 62 63"));               // V10
	Decoder d1 = dec("03 00 00 00 61 62 63");
	assert(d1.get_string()!! == "abc");
	assert(enc_string("水") == unhex("03 00 00 00 E6 B0 B4"));                // V13: 3 bytes, one character
	Decoder d2 = dec("03 00 00 00 E6 B0 B4");
	String s = d2.get_string()!!;
	assert(s.len == 3 && s == "水");
}

fn void fixtures_bytestring() @test
{
	char[2] two = { 0xAA, 0xBB };
	assert(enc_bytes(&two) == unhex("02 00 00 00 AA BB"));                    // V14
	Decoder d1 = dec("02 00 00 00 AA BB");
	assert(d1.get_bytestring()!! == unhex("AA BB"));
	char[2] one_two = { 1, 2 };
	assert(enc_bytes(&one_two) == unhex("02 00 00 00 01 02"));
}

fn void fixtures_guid() @test
{
	Guid g = { .d1 = 0x72962B91, .d2 = 0xFA75, .d3 = 0x4AE6, .d4 = { 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63 } };
	assert(enc_guid(g) == unhex("91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63"));   // V20
	Decoder d = dec("91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63");
	Guid r = d.get_guid()!!;
	assert(guid_equals(r, g));
}

// V11, V12, V15: null and empty are different on the wire and in memory, and both round trip.
fn void null_vs_empty_string() @test
{
	assert(enc_string(null_string()) == unhex("FF FF FF FF"));                // V11
	assert(enc_string(empty_string()) == unhex("00 00 00 00"));               // V12
	assert(enc_string((String)"") == unhex("00 00 00 00"));
	Decoder dn = dec("FF FF FF FF");
	String n = dn.get_string()!!;
	assert(is_null(n) && n.len == 0);
	Decoder de = dec("00 00 00 00");
	String e = de.get_string()!!;
	assert(!is_null(e) && e.len == 0);
	String zero;                                                              // the zero value is null
	assert(is_null(zero));
	assert(enc_string(zero) == unhex("FF FF FF FF"));
}

fn void null_vs_empty_bytestring() @test
{
	assert(enc_bytes(null_bytes()) == unhex("FF FF FF FF"));                  // V15
	assert(enc_bytes(empty_bytes()) == unhex("00 00 00 00"));
	Decoder dn = dec("FF FF FF FF");
	char[] n = dn.get_bytestring()!!;
	assert(bytes_is_null(n) && n.len == 0);
	Decoder de = dec("00 00 00 00");
	char[] e = de.get_bytestring()!!;
	assert(!bytes_is_null(e) && e.len == 0);
}

// decode -> encode keeps the distinction (round trip of the four vectors)
fn void null_vs_empty_roundtrip() @test
{
	foreach (String hex : { "FF FF FF FF", "00 00 00 00" })
	{
		Decoder d = dec(hex);
		String s = d.get_string()!!;
		assert(enc_string(s) == unhex(hex));
		Decoder d2 = dec(hex);
		char[] b = d2.get_bytestring()!!;
		assert(enc_bytes(b) == unhex(hex));
	}
}

fn void prefix_sweep_strings() @test
{
	prefix_sweep("03 00 00 00 61 62 63", STRING);
	prefix_sweep("FF FF FF FF", STRING);
	prefix_sweep("00 00 00 00", STRING);
	prefix_sweep("03 00 00 00 E6 B0 B4", STRING);
	prefix_sweep("02 00 00 00 AA BB", BYTES);
	prefix_sweep("FF FF FF FF", BYTES);
	prefix_sweep("00 00 00 00", BYTES);
	prefix_sweep("91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63", GUID);
}

fn void sizer_strings() @test
{
	assert(size_string("abc") == 7);
	assert(size_string(null_string()) == 4);
	assert(size_string(empty_string()) == 4);
	assert(size_string("水") == 7);
}

fn void errors_string_lengths() @test
{
	assert(fails_with("10 00 00 00 41 41", STRING, TRUNCATED));               // M40: length 16, 2 bytes
	assert(fails_with("64 00 00 00 41 42 43", STRING, TRUNCATED));            // length 100, 3 bytes
	assert(fails_with("FE FF FF FF", STRING, BAD_LENGTH));                    // M41: -2
	assert(fails_with("00 00 00 80", STRING, BAD_LENGTH));                    // M42: INT32_MIN
	assert(fails_with("FF FF FF 7F", STRING, BAD_LENGTH));                    // M43: INT32_MAX
	assert(fails_with("FE FF FF FF", BYTES, BAD_LENGTH));
	assert(fails_with("FF FF FF 7F", BYTES, BAD_LENGTH));
	assert(fails_with("0F 00 00 00 41", BYTES, TRUNCATED));
	assert(fails_with("0F", U32, TRUNCATED));
}

fn void errors_guid_truncated() @test
{
	assert(fails_with("91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF", GUID, TRUNCATED));   // M78: 15 bytes
}

fn void utf8_validation() @test
{
	assert(fails_with("02 00 00 00 C3 28", STRING, BAD_ENCODING));           // M44: invalid continuation
	assert(fails_with("02 00 00 00 C0 80", STRING, BAD_ENCODING));            // overlong
	assert(fails_with("03 00 00 00 ED A0 80", STRING, BAD_ENCODING));         // surrogate
	assert(fails_with("04 00 00 00 F4 90 80 80", STRING, BAD_ENCODING));      // above U+10FFFF
	assert(fails_with("01 00 00 00 80", STRING, BAD_ENCODING));               // lone continuation byte
	assert(fails_with("03 00 00 00 E2 82 41", STRING, BAD_ENCODING));
	assert(decodes_fully("04 00 00 00 F0 9F 98 80", STRING));                 // U+1F600
	assert(decodes_fully("03 00 00 00 E2 82 AC", STRING));                    // euro sign
	assert(decodes_fully("02 00 00 00 C3 A9", STRING));
	// a ByteString is not text: any bytes are fine
	assert(decodes_fully("02 00 00 00 C3 28", BYTES));
}

// M45: an embedded NUL is accepted; the string is never treated as a C string.
fn void utf8_embedded_nul() @test
{
	Decoder d = dec("03 00 00 00 41 00 42");
	String s = d.get_string()!!;
	assert(s.len == 3 && ((char[])s)[1] == 0);
	assert(enc_string(s) == unhex("03 00 00 00 41 00 42"));
	Decoder d2 = dec("01 00 00 00 00");
	assert(d2.get_string()!!.len == 1);
}

// Lenient mode (Decoder.validate_utf8 = false): invalid bytes become U+FFFD instead of failing.
fn void utf8_lenient_replaces() @test
{
	Decoder d = dec("04 00 00 00 41 C3 28 42");
	d.validate_utf8 = false;
	String s = d.get_string()!!;
	assert(s == unhex("41 EF BF BD 28 42"));
	assert(utf8_valid((char[])s));
	Decoder ok = dec("02 00 00 00 C3 A9");
	ok.validate_utf8 = false;
	assert(ok.get_string()!! == unhex("C3 A9"));
}
