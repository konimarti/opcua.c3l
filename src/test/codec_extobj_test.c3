module opcua;

// ExtensionObject kept as received (OPC 10000-6 5.2.2.15). Vectors EO1-EO3, M68-M70, M73.

fn void fixtures_extension_object() @test
{
	ExtensionObject eo1 = { .type_id = nodeid_num(0, 0) };
	assert(enc_ext(eo1) == unhex("00 00 00"));                                            // EO1
	check_vector("00 00 00", EXTOBJ);
	ExtensionObject eo2 = { .type_id = nodeid_num(1, 5000), .encoding = 1, .body = unhex("AA BB CC") };
	assert(enc_ext(eo2) == unhex("01 01 88 13 01 03 00 00 00 AA BB CC"));                 // EO2
	check_vector("01 01 88 13 01 03 00 00 00 AA BB CC", EXTOBJ);
	ExtensionObject eo3 = { .type_id = nodeid_num(1, 5000), .encoding = 2, .body = (char[])"<a/>" };
	assert(enc_ext(eo3) == unhex("01 01 88 13 02 04 00 00 00 3C 61 2F 3E"));              // EO3: XmlElement body kept opaquely
	check_vector("01 01 88 13 02 04 00 00 00 3C 61 2F 3E", EXTOBJ);
	ExtensionObject dd = { .type_id = nodeid_num(1, 999), .encoding = 1, .body = unhex("01 02") };
	assert(enc_ext(dd) == unhex("01 01 E7 03 01 02 00 00 00 01 02"));
	check_vector("01 01 E7 03 01 02 00 00 00 01 02", EXTOBJ);
}

fn void extobj_raw_fields() @test
{
	Decoder d = dec("01 01 88 13 01 03 00 00 00 AA BB CC");
	ExtensionObject x = d.get_extension_object()!!;
	assert(nodeid_equals(x.type_id, nodeid_num(1, 5000)) && x.encoding == 1 && x.body == unhex("AA BB CC"));
	Decoder none = dec("00 00 00");
	ExtensionObject n = none.get_extension_object()!!;
	assert(n.encoding == 0 && bytes_is_null(n.body));
	Decoder xml = dec("01 01 88 13 02 04 00 00 00 3C 61 2F 3E");
	ExtensionObject xx = xml.get_extension_object()!!;
	assert(xx.encoding == 2 && xx.body == (char[])"<a/>");
}

fn void errors_extension_object() @test
{
	assert(fails_with("01 01 88 13 03 00 00 00 00", EXTOBJ, BAD_ENCODING));              // M68: encoding byte 3
	assert(fails_with("01 01 88 13 01 10 00 00 00 AA", EXTOBJ, TRUNCATED));               // M69: body length 16, 1 byte present
	assert(fails_with("01 01 88 13", EXTOBJ, TRUNCATED));
	assert(fails_with("01 01 88 13 01 FE FF FF FF", EXTOBJ, BAD_LENGTH));
	ExtensionObject bad = { .encoding = 3 };
	Encoder e = encoder_sizer();
	assert(@fails(e.put_extension_object(bad), BAD_ENCODING));
}

// M70: a ByteString body of length -1 is accepted and stays null (re-encoded as -1).
fn void extobj_raw_null_body() @test
{
	check_vector("01 01 88 13 01 FF FF FF FF", EXTOBJ);
	Decoder d = dec("01 01 88 13 01 FF FF FF FF");
	ExtensionObject x = d.get_extension_object()!!;
	assert(x.encoding == 1 && bytes_is_null(x.body));
	check_vector("01 01 88 13 01 00 00 00 00", EXTOBJ);                                   // an empty body is not a null body
	Decoder e = dec("01 01 88 13 01 00 00 00 00");
	assert(!bytes_is_null(e.get_extension_object()!!.body));
}

// M73: a null type id with encoding 1 and a body is accepted (policy) and must not crash.
fn void extobj_raw_null_type_with_body() @test
{
	check_vector("00 00 01 02 00 00 00 AA BB", EXTOBJ);
}
