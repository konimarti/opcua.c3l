module opcua;

// NodeId binary encoding (OPC 10000-6 5.2.2.9), identity (10000-3 8.2) and text form (10000-6 5.3.1.10).
// Vectors N1-N11, M46-M50 plus extras.

fn Guid test_guid()
{
	return { .d1 = 0x72962B91, .d2 = 0xFA75, .d3 = 0x4AE6, .d4 = { 0x8D, 0x28, 0xB4, 0x04, 0xDC, 0x7D, 0xAF, 0x63 } };
}

// decode == expected; when `canonical`, encode(decode(hex)) == hex as well; the sizer agrees with the encoder.
fn void check_nodeid(String hex, NodeId expected, bool canonical = true)
{
	Decoder d = dec(hex);
	NodeId got = d.get_nodeid()!!;
	assert(d.remaining() == 0, "all bytes consumed");
	assert(nodeid_equals(got, expected), "decoded value");
	if (canonical) assert(enc_nodeid(got) == unhex(hex), "re-encoded bytes");
	assert(enc_nodeid(expected).len == size_nodeid(expected), "sizer");
	prefix_sweep(hex, NODEID);
}

fn void fixtures_nodeid_numeric() @test
{
	check_nodeid("00 48", nodeid_num(0, 72));                                  // N1
	check_nodeid("00 00", nodeid_num(0, 0));                                   // N2 null NodeId
	check_nodeid("01 01 E8 03", nodeid_num(1, 1000));                          // N3
	check_nodeid("01 00 D2 08", nodeid_num(0, 2258));                          // N4
	check_nodeid("02 2C 01 70 11 01 00", nodeid_num(300, 70000));              // N5
	check_nodeid("00 55", nodeid_num(0, 85));                                  // extra
	check_nodeid("01 02 E8 03", nodeid_num(2, 1000));                          // extra
}

fn void fixtures_nodeid_string() @test
{
	check_nodeid("03 02 00 05 00 00 00 48 65 6C 6C 6F", nodeid_str(2, "Hello"));                    // N6
	check_nodeid("03 01 00 06 00 00 00 48 6F 74 E6 B0 B4", nodeid_str(1, "Hot水"));                  // N7
	check_nodeid("03 01 00 03 00 00 00 48 6F 74", nodeid_str(1, "Hot"));                            // extra
}

fn void fixtures_nodeid_guid_opaque() @test
{
	NodeId g = { .ns = 2, .kind = GUID, .guid = test_guid() };
	check_nodeid("04 02 00 91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63", g);                    // N8
	char[2] ab = { 0xAA, 0xBB };
	NodeId o = { .ns = 3, .kind = OPAQUE, .bytes = &ab };
	check_nodeid("05 03 00 02 00 00 00 AA BB", o);                                                  // N9
}

// N10: a non-minimal Numeric encoding is accepted and equals the compact form; the encoder writes the compact form.
fn void fixtures_nodeid_non_minimal() @test
{
	check_nodeid("02 00 00 05 00 00 00", nodeid_num(0, 5), false);
	Decoder d = dec("02 00 00 05 00 00 00");
	NodeId n = d.get_nodeid()!!;
	assert(enc_nodeid(n) == unhex("00 05"));
	Decoder d4 = dec("01 00 05 00");                       // FourByte i=5 is the same node
	assert(nodeid_equals(d4.get_nodeid()!!, nodeid_num(0, 5)));
}

// N11: a String NodeId with a null identifier is accepted (decision); null is kept on re-encode.
fn void fixtures_nodeid_null_string_identifier() @test
{
	Decoder d = dec("03 00 00 FF FF FF FF");
	NodeId n = d.get_nodeid()!!;
	assert(n.kind == STRING && is_null(n.str));
	assert(enc_nodeid(n) == unhex("03 00 00 FF FF FF FF"));
	prefix_sweep("03 00 00 FF FF FF FF", NODEID);
}

// The encoder picks the smallest numeric form.
fn void encoder_picks_smallest_form() @test
{
	assert(enc_nodeid(nodeid_num(0, 255)) == unhex("00 FF"));
	assert(enc_nodeid(nodeid_num(0, 256)) == unhex("01 00 00 01"));
	assert(enc_nodeid(nodeid_num(255, 65535)) == unhex("01 FF FF FF"));
	assert(enc_nodeid(nodeid_num(256, 1)) == unhex("02 00 01 01 00 00 00"));
	assert(enc_nodeid(nodeid_num(0, 65536)) == unhex("02 00 00 00 00 01 00"));
	assert(enc_nodeid(nodeid_num(1, 70000)) == unhex("02 01 00 70 11 01 00"));
}

fn void errors_nodeid() @test
{
	assert(fails_with("01 01 E8", NODEID, TRUNCATED));                         // M46
	assert(fails_with("06 00 00", NODEID, BAD_NODEID));                        // M47
	assert(fails_with("0F 00 00", NODEID, BAD_NODEID));                        // M48
	assert(fails_with("80 00 00", NODEID, BAD_NODEID));                        // M49: ExpandedNodeId flag in a plain NodeId
	assert(fails_with("40 00 00", NODEID, BAD_NODEID));
	assert(fails_with("03 00 00 05 00 00 00 41", NODEID, TRUNCATED));          // M50
	assert(fails_with("03 00 00 FE FF FF FF", NODEID, BAD_LENGTH));
	assert(fails_with("", NODEID, TRUNCATED));
}

fn void identity_equals_and_hash() @test
{
	NodeId a = nodeid_num(0, 5);
	Decoder d = dec("02 00 00 05 00 00 00");
	NodeId b = d.get_nodeid()!!;
	assert(nodeid_equals(a, b));
	assert(nodeid_hash(a) == nodeid_hash(b));
	assert(!nodeid_equals(nodeid_num(0, 5), nodeid_num(1, 5)));
	assert(!nodeid_equals(nodeid_num(0, 5), nodeid_num(0, 6)));
	assert(!nodeid_equals(nodeid_num(1, 5), nodeid_str(1, "5")));
	assert(nodeid_equals(nodeid_str(1, "Foo"), nodeid_str(1, "Foo")));
	assert(!nodeid_equals(nodeid_str(1, "Foo"), nodeid_str(1, "foo")));              // case sensitive
	assert(nodeid_hash(nodeid_str(1, "Foo")) == nodeid_hash(nodeid_str(1, "Foo")));
	assert(nodeid_hash(nodeid_str(1, "Foo")) != nodeid_hash(nodeid_str(1, "foo")));
	assert(nodeid_hash(nodeid_num(0, 5)) != nodeid_hash(nodeid_num(0, 6)));
	assert(nodeid_equals(nodeid_str(1, null_string()), nodeid_str(1, empty_string())));
	assert(nodeid_hash(nodeid_str(1, null_string())) == nodeid_hash(nodeid_str(1, empty_string())));
	NodeId g1 = { .ns = 2, .kind = GUID, .guid = test_guid() };
	NodeId g2 = { .ns = 2, .kind = GUID, .guid = test_guid() };
	assert(nodeid_equals(g1, g2) && nodeid_hash(g1) == nodeid_hash(g2));
	g2.guid.d4[7] = 0;
	assert(!nodeid_equals(g1, g2));
}

fn void text_parse() @test
{
	assert(nodeid_equals(parse_nodeid("i=85", tmem)!!, nodeid_num(0, 85)));
	assert(nodeid_equals(parse_nodeid("ns=2;s=Foo", tmem)!!, nodeid_str(2, "Foo")));
	assert(nodeid_equals(parse_nodeid("ns=1;i=1000", tmem)!!, nodeid_num(1, 1000)));
	assert(nodeid_equals(parse_nodeid("ns=65535;i=4294967295", tmem)!!, nodeid_num(65535, 4294967295)));
	assert(nodeid_equals(parse_nodeid("s=a;b=c", tmem)!!, nodeid_str(0, "a;b=c")));
	assert(nodeid_equals(parse_nodeid("s=", tmem)!!, nodeid_str(0, empty_string())));
	NodeId g = parse_nodeid("ns=2;g=72962B91-FA75-4AE6-8D28-B404DC7DAF63", tmem)!!;
	assert(g.kind == GUID && g.ns == 2 && guid_equals(g.guid, test_guid()));
	NodeId lower = { .ns = 0, .kind = GUID, .guid = test_guid() };
	assert(nodeid_equals(parse_nodeid("g=72962b91-fa75-4ae6-8d28-b404dc7daf63", tmem)!!, lower));
	NodeId o = parse_nodeid("ns=3;b=qrs=", tmem)!!;                          // base64 of AA BB
	assert(o.kind == OPAQUE && o.ns == 3 && o.bytes == unhex("AA BB"));
}

fn void text_parse_errors() @test
{
	foreach (String bad : { "", "x=1", "i=", "i=abc", "i=4294967296", "ns=2", "ns=;i=1", "ns=65536;i=1", "ns=2;", "ns=2;x=1",
		"g=short", "g=72962B91-FA75-4AE6-8D28-B404DC7DAF6", "g=72962B91-FA75-4AE6-8D28-B404DC7DAF6Z", "b=!!!!", "i", "i1" })
	{
		if (try n = parse_nodeid(bad, tmem))
		{
			unreachable("must not parse");
		}
	}
	assert(@fails(parse_nodeid("x=1", tmem), BAD_NODEID));
}

fn void text_roundtrip() @test
{
	char[2] ab = { 0xAA, 0xBB };
	NodeId[] ids = {
		nodeid_num(0, 85), nodeid_num(2, 1000), nodeid_num(65535, 4294967295), nodeid_str(1, "Hot"), nodeid_str(4, "a;b=c"),
		{ .ns = 2, .kind = GUID, .guid = test_guid() }, { .ns = 3, .kind = OPAQUE, .bytes = &ab },
	};
	foreach (id : ids)
	{
		String text = nodeid_to_string(id, tmem);
		NodeId back = parse_nodeid(text, tmem)!!;
		assert(nodeid_equals(id, back), "text form round trip");
	}
	assert(nodeid_to_string(nodeid_num(0, 85), tmem) == "i=85");
	assert(nodeid_to_string(nodeid_str(2, "Foo"), tmem) == "ns=2;s=Foo");
	NodeId g = { .ns = 2, .kind = GUID, .guid = test_guid() };
	assert(nodeid_to_string(g, tmem) == "ns=2;g=72962b91-fa75-4ae6-8d28-b404dc7daf63");
	NodeId o = { .ns = 3, .kind = OPAQUE, .bytes = &ab };
	assert(nodeid_to_string(o, tmem) == "ns=3;b=qrs=");
}
