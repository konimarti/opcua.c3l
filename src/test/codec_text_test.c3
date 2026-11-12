module opcua;

// QualifiedName, LocalizedText, ExpandedNodeId and DateTime (OPC 10000-6 5.2.2.5, 5.2.2.10, 5.2.2.13, 5.2.2.14).
// Vectors V16-V19, V23-V26, X1-X4, M66, M67, M79 plus extras.

fn void fixtures_qualified_name() @test
{
	assert(enc_qname({ 2, "Foo" }) == unhex("02 00 03 00 00 00 46 6F 6F"));     // V23
	check_vector("02 00 03 00 00 00 46 6F 6F", QNAME);
	assert(enc_qname({ 2, "A" }) == unhex("02 00 01 00 00 00 41"));
	check_vector("02 00 01 00 00 00 41", QNAME);
	Decoder d = dec("02 00 03 00 00 00 46 6F 6F");
	QualifiedName q = d.get_qualified_name()!!;
	assert(q.ns == 2 && q.name == "Foo");
	check_vector("00 00 FF FF FF FF", QNAME);                                   // null name
}

fn void fixtures_localized_text() @test
{
	assert(enc_ltext({ .locale = "en", .text = "Hi" }) == unhex("03 02 00 00 00 65 6E 02 00 00 00 48 69"));   // V24
	check_vector("03 02 00 00 00 65 6E 02 00 00 00 48 69", LTEXT);
	assert(enc_ltext({ .text = "Hi" }) == unhex("02 02 00 00 00 48 69"));        // V25
	check_vector("02 02 00 00 00 48 69", LTEXT);
	assert(enc_ltext({}) == unhex("00"));                                         // V26: both null
	check_vector("00", LTEXT);
	Decoder d = dec("03 02 00 00 00 65 6E 02 00 00 00 48 69");
	LocalizedText t = d.get_localized_text()!!;
	assert(t.locale == "en" && t.text == "Hi");
	Decoder dn = dec("00");
	LocalizedText n = dn.get_localized_text()!!;
	assert(is_null(n.locale) && is_null(n.text));
	// present but empty is not the same as absent
	assert(enc_ltext({ .locale = empty_string(), .text = null_string() }) == unhex("01 00 00 00 00"));
	check_vector("01 00 00 00 00", LTEXT);
}

fn void errors_localized_text() @test
{
	assert(fails_with("04", LTEXT, BAD_ENCODING));                                // M66: reserved bit
	assert(fails_with("80 00", LTEXT, BAD_ENCODING));
	assert(fails_with("02 10 00 00 00 41", LTEXT, TRUNCATED));                    // M67: truncated text
}

fn void fixtures_expanded_nodeid() @test
{
	ExpandedNodeId x1 = { .id = nodeid_num(0, 72), .namespace_uri = "urn:a", .server_index = 5 };
	assert(enc_xnode(x1) == unhex("C0 48 05 00 00 00 75 72 6E 3A 61 05 00 00 00"));   // X1
	check_vector("C0 48 05 00 00 00 75 72 6E 3A 61 05 00 00 00", XNODEID);
	ExpandedNodeId x2 = { .id = nodeid_num(0, 72), .namespace_uri = "urn:a" };
	assert(enc_xnode(x2) == unhex("80 48 05 00 00 00 75 72 6E 3A 61"));               // X2
	check_vector("80 48 05 00 00 00 75 72 6E 3A 61", XNODEID);
	ExpandedNodeId x3 = { .id = nodeid_num(0, 72), .server_index = 7 };
	assert(enc_xnode(x3) == unhex("40 48 07 00 00 00"));                              // X3
	check_vector("40 48 07 00 00 00", XNODEID);
	ExpandedNodeId x4 = { .id = nodeid_num(0, 72) };
	assert(enc_xnode(x4) == unhex("00 48"));                                          // X4
	check_vector("00 48", XNODEID);
	Decoder d = dec("C0 48 05 00 00 00 75 72 6E 3A 61 05 00 00 00");
	ExpandedNodeId r = d.get_expanded_nodeid()!!;
	assert(nodeid_equals(r.id, nodeid_num(0, 72)) && r.namespace_uri == "urn:a" && r.server_index == 5);
	// the namespace URI flag with an empty URI is kept (null = flag absent, empty = flag set)
	ExpandedNodeId empty_uri = { .id = nodeid_num(0, 72), .namespace_uri = empty_string() };
	assert(enc_xnode(empty_uri) == unhex("80 48 00 00 00 00"));
	check_vector("80 48 00 00 00 00", XNODEID);
	// the flags work on every NodeId encoding
	ExpandedNodeId s = { .id = nodeid_str(1, "x"), .namespace_uri = "u" };
	assert(enc_xnode(s) == unhex("83 01 00 01 00 00 00 78 01 00 00 00 75"));
	check_vector("83 01 00 01 00 00 00 78 01 00 00 00 75", XNODEID);
}

// A flag byte in a plain NodeId is still rejected, and an ExpandedNodeId decodes with every flag combination.
fn void expanded_nodeid_flags_vs_plain() @test
{
	assert(fails_with("C0 48 05 00 00 00 75 72 6E 3A 61 05 00 00 00", NODEID, BAD_NODEID));
	assert(fails_with("80 48 05 00 00 00", XNODEID, TRUNCATED));
}

fn void fixtures_datetime() @test
{
	check_vector("00 00 00 00 00 00 00 00", DATETIME);                                // V16
	check_vector("00 80 3E D5 DE B1 9D 01", DATETIME);                                // V17
	check_vector("00 40 6D 25 EB 53 BF 01", DATETIME);                                // V18
	check_vector("FF FF FF FF FF FF FF 7F", DATETIME);                                // V19
	check_vector("00 00 00 00 00 00 00 80", DATETIME);                                // M79: INT64_MIN is accepted, kept as is
	assert(enc_datetime((UaDateTime)0) == unhex("00 00 00 00 00 00 00 00"));
	assert(enc_datetime((UaDateTime)116444736000000000) == unhex("00 80 3E D5 DE B1 9D 01"));
	assert(enc_datetime((UaDateTime)125911584000000000) == unhex("00 40 6D 25 EB 53 BF 01"));
	assert(enc_datetime((UaDateTime)long::max) == unhex("FF FF FF FF FF FF FF 7F"));
	Decoder d = dec("00 80 3E D5 DE B1 9D 01");
	assert((long)d.get_datetime()!! == 116444736000000000);
}

fn void datetime_conversion() @test
{
	assert((long)datetime_from_unix_ms(0) == 116444736000000000);                      // 1970-01-01
	assert(datetime_to_unix_ms((UaDateTime)116444736000000000) == 0);
	assert((long)datetime_from_unix_ms(946684800000) == 125911584000000000);            // 2000-01-01
	assert(datetime_to_unix_ms((UaDateTime)125911584000000000) == 946684800000);
	assert((long)datetime_from_unix_ms(-11644473600000) == 0);                          // 1601-01-01
	assert(datetime_to_unix_ms((UaDateTime)0) == -11644473600000);
	// saturation, no overflow
	assert((long)datetime_from_unix_ms(long::min) == 0);
	assert((long)datetime_from_unix_ms(long::max) == long::max);
	assert((long)datetime_from_unix_ms(long::max / 2) == long::max);
	assert(datetime_to_unix_ms((UaDateTime)long::min) == -11644473600000);              // negative = not specified
	assert(datetime_to_unix_ms((UaDateTime)long::max) == long::max / 10000 - 11644473600000);
	long ms = 1700000000123;
	assert(datetime_to_unix_ms(datetime_from_unix_ms(ms)) == ms);
}

fn void errors_datetime() @test
{
	assert(fails_with("00 00 00 00 00 00 00", DATETIME, TRUNCATED));
}
