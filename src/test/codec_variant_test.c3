module opcua;

// Variant (OPC 10000-6 5.2.2.16). Vectors VA1-VA14, M51-M62 plus extras.

fn Variant arr_i32(int[] a) => { .type = INT32, .is_array = true, .array.i32 = a };

fn void fixtures_variant_scalars() @test
{
	assert(enc_variant({}) == unhex("00"));                                               // VA1
	check_vector("00", VARIANT);
	assert(enc_variant(variant_bool(true)) == unhex("01 01"));                            // VA2
	check_vector("01 01", VARIANT);
	assert(enc_variant(variant_i32(42)) == unhex("06 2A 00 00 00"));                      // VA3
	check_vector("06 2A 00 00 00", VARIANT);
	assert(enc_variant(variant_string("abc")) == unhex("0C 03 00 00 00 61 62 63"));       // VA4
	check_vector("0C 03 00 00 00 61 62 63", VARIANT);
	assert(enc_variant(variant_f64(1.0)) == unhex("0B 00 00 00 00 00 00 F0 3F"));         // VA5
	check_vector("0B 00 00 00 00 00 00 F0 3F", VARIANT);
	LocalizedText lt = { .locale = "en", .text = "Hi" };
	Variant vlt = { .type = LOCALIZEDTEXT, .scalar.ltext = &lt };
	assert(enc_variant(vlt) == unhex("15 03 02 00 00 00 65 6E 02 00 00 00 48 69"));      // VA11
	check_vector("15 03 02 00 00 00 65 6E 02 00 00 00 48 69", VARIANT);
	Variant vdt = { .type = DATETIME, .scalar.dt = (UaDateTime)116444736000000000 };
	assert(enc_variant(vdt) == unhex("0D 00 80 3E D5 DE B1 9D 01"));                      // VA12
	check_vector("0D 00 80 3E D5 DE B1 9D 01", VARIANT);
	char[2] ab = { 0xAA, 0xBB };
	Variant vbs = { .type = BYTESTRING, .scalar.bytes = &ab };
	assert(enc_variant(vbs) == unhex("0F 02 00 00 00 AA BB"));                            // VA13
	check_vector("0F 02 00 00 00 AA BB", VARIANT);
	Variant vsc = { .type = STATUSCODE, .scalar.sc = (StatusCode)0x80340000 };
	assert(enc_variant(vsc) == unhex("13 00 00 34 80"));                                  // VA14
	check_vector("13 00 00 34 80", VARIANT);
	Decoder d = dec("06 2A 00 00 00");
	Variant v = d.get_variant()!!;
	assert(v.type == INT32 && !v.is_array && v.scalar.i32 == 42 && v.count() == 1);
}

fn void fixtures_variant_arrays() @test
{
	int[3] three = { 1, 2, 3 };
	assert(enc_variant(variant_i32_array(&three)) == unhex("86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00"));   // VA6
	check_vector("86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00", VARIANT);
	Decoder d = dec("86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00");
	Variant v = d.get_variant()!!;
	assert(v.type == INT32 && v.is_array && v.count() == 3 && v.array.i32[2] == 3 && v.dims.len == 0);
	// matrix 2 x 3 (VA9) and the extra 2 x 2
	int[6] six = { 1, 2, 3, 4, 5, 6 };
	uint[2] d23 = { 2, 3 };
	Variant m = arr_i32(&six);
	m.dims = &d23;
	String va9 = "C6 06 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 02 00 00 00 02 00 00 00 03 00 00 00";
	assert(enc_variant(m) == unhex(va9));
	check_vector(va9, VARIANT);
	Decoder dm = dec(va9);
	Variant mv = dm.get_variant()!!;
	assert(mv.dims.len == 2 && mv.dims[0] == 2 && mv.dims[1] == 3 && mv.count() == 6);
	int[4] four = { 1, 2, 3, 4 };
	uint[2] d22 = { 2, 2 };
	Variant m2 = arr_i32(&four);
	m2.dims = &d22;
	String mx = "C6 04 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 02 00 00 00 02 00 00 00 02 00 00 00";
	assert(enc_variant(m2) == unhex(mx));
	check_vector(mx, VARIANT);
}

// VA7 (empty) and VA8 (null) arrays stay distinct through decode and encode.
fn void variant_null_empty() @test
{
	Decoder de = dec("86 00 00 00 00");
	Variant e = de.get_variant()!!;
	assert(e.is_array && e.count() == 0 && !array_data_is_null(INT32, &e.array));
	Decoder dn = dec("86 FF FF FF FF");
	Variant n = dn.get_variant()!!;
	assert(n.is_array && n.count() == 0 && array_data_is_null(INT32, &n.array));
	check_vector("86 00 00 00 00", VARIANT);
	check_vector("86 FF FF FF FF", VARIANT);
	assert(enc_variant(arr_i32({})) == unhex("86 FF FF FF FF"));
	int[1] one = { 7 };
	assert(enc_variant(arr_i32(one[:0])) == unhex("86 00 00 00 00"));
}

// VA10: an array of Variants; every element is a full Variant with its own mask.
fn void fixtures_variant_of_variants() @test
{
	Variant[] items = pair(Variant, variant_i32(42), (Variant){});
	Variant v = { .type = VARIANT, .is_array = true, .array.variant = items };
	assert(enc_variant(v) == unhex("98 02 00 00 00 06 2A 00 00 00 00"));
	check_vector("98 02 00 00 00 06 2A 00 00 00 00", VARIANT);
}

fn Variant sample(BuiltIn t, bool array)
{
	Variant v = { .type = t, .is_array = array };
	NodeId nid = nodeid_str(2, "n");
	ExpandedNodeId xn = { .id = nodeid_num(1, 7), .namespace_uri = "urn:x", .server_index = 3 };
	QualifiedName qn = { 3, "q" };
	LocalizedText lt = { .locale = "en", .text = "t" };
	ExtensionObject eo = { .type_id = nodeid_num(1, 5000), .encoding = 1, .body = unhex("01 02") };
	DataValue dv = { .value = variant_i32(5), .has_value = true, .status = (StatusCode)0x80340000, .source_ts = (UaDateTime)5 };
	DiagnosticInfo di = { .present = 1, .symbolic_id = 9, .additional_info = "a" };
	Guid g = { .d1 = 1, .d2 = 2, .d3 = 3, .d4 = { 1, 2, 3, 4, 5, 6, 7, 8 } };
	if (!array)
	{
		switch (t)
		{
			case BOOLEAN: v.scalar.b = true;
			case SBYTE: v.scalar.i8 = -5;
			case BYTE: v.scalar.u8 = 200;
			case INT16: v.scalar.i16 = -300;
			case UINT16: v.scalar.u16 = 60000;
			case INT32: v.scalar.i32 = -70000;
			case UINT32: v.scalar.u32 = 4000000000;
			case INT64: v.scalar.i64 = -5000000000;
			case UINT64: v.scalar.u64 = 10000000000000;
			case FLOAT: v.scalar.f32 = 1.25f;
			case DOUBLE: v.scalar.f64 = -2.5;
			case STRING: v.scalar.str = "str";
			case XMLELEMENT: v.scalar.str = "<a/>";
			case DATETIME: v.scalar.dt = (UaDateTime)123456789;
			case GUID: v.scalar.guid = g;
			case BYTESTRING: v.scalar.bytes = unhex("01 02 03");
			case STATUSCODE: v.scalar.sc = (StatusCode)0x80340000;
			case NODEID: v.scalar.node_id = alloc::new_try(tmem, NodeId, nid)!!;
			case EXPANDEDNODEID: v.scalar.xnode_id = alloc::new_try(tmem, ExpandedNodeId, xn)!!;
			case QUALIFIEDNAME: v.scalar.qname = alloc::new_try(tmem, QualifiedName, qn)!!;
			case LOCALIZEDTEXT: v.scalar.ltext = alloc::new_try(tmem, LocalizedText, lt)!!;
			case EXTENSIONOBJECT: v.scalar.ext = alloc::new_try(tmem, ExtensionObject, eo)!!;
			case DATAVALUE: v.scalar.dv = alloc::new_try(tmem, DataValue, dv)!!;
			case DIAGNOSTICINFO: v.scalar.diag = alloc::new_try(tmem, DiagnosticInfo, di)!!;
			default: unreachable("no scalar sample");
		}
		return v;
	}
	switch (t)
	{
		case BOOLEAN: v.array.b = pair(bool, true, false);
		case SBYTE: v.array.i8 = pair(ichar, -1, 1);
		case BYTE: v.array.u8 = pair(char, 1, 255);
		case INT16: v.array.i16 = pair(short, -1, 1);
		case UINT16: v.array.u16 = pair(ushort, 1, 65535);
		case INT32: v.array.i32 = pair(int, -1, 1);
		case UINT32: v.array.u32 = pair(uint, 1, 4000000000);
		case INT64: v.array.i64 = pair(long, -1, 1);
		case UINT64: v.array.u64 = pair(ulong, 1, 10000000000000);
		case FLOAT: v.array.f32 = pair(float, 1.5f, -2.5f);
		case DOUBLE: v.array.f64 = pair(double, 1.5, -2.5);
		case STRING: v.array.str = pair(String, (String)"a", null_string());
		case XMLELEMENT: v.array.str = pair(String, (String)"<a/>", (String)"<b/>");
		case DATETIME: v.array.dt = pair(UaDateTime, (UaDateTime)1, (UaDateTime)2);
		case GUID: v.array.guid = pair(Guid, g, g);
		case BYTESTRING: v.array.bytes = pair(char[], unhex("01"), null_bytes());
		case STATUSCODE: v.array.sc = pair(StatusCode, (StatusCode)0, (StatusCode)0x80340000);
		case NODEID: v.array.node_id = pair(NodeId, nid, nodeid_num(0, 85));
		case EXPANDEDNODEID: v.array.xnode_id = pair(ExpandedNodeId, xn, xn);
		case QUALIFIEDNAME: v.array.qname = pair(QualifiedName, qn, qn);
		case LOCALIZEDTEXT: v.array.ltext = pair(LocalizedText, lt, (LocalizedText){});
		case EXTENSIONOBJECT: v.array.ext = pair(ExtensionObject, eo, eo);
		case DATAVALUE: v.array.dv = pair(DataValue, dv, (DataValue){});
		case VARIANT: v.array.variant = pair(Variant, variant_i32(1), (Variant){});
		case DIAGNOSTICINFO: v.array.diag = pair(DiagnosticInfo, di, (DiagnosticInfo){});
		default: unreachable("no array sample");
	}
	return v;
}

// Every built-in type id 1..25, scalar (not Variant) and array: encode, decode, encode again; sweep all prefixes.
fn void variant_all_types() @test
{
	for (char id = 1; id <= 25; id++)
	{
		BuiltIn t = (BuiltIn)id;
		for (int a = 0; a < 2; a++)
		{
			if (t == VARIANT && a == 0) continue;           // a scalar Variant inside a Variant is rejected
			Variant v = sample(t, a == 1);
			char[] bytes = enc_variant(v);
			assert(bytes[0] == (id | (a == 1 ? 0x80 : 0)), "mask byte");
			String hex = tohex(bytes);
			check_vector(hex, VARIANT);
			Decoder d = decoder(bytes, tmem);
			Variant back = d.get_variant()!!;
			assert(back.type == t && back.is_array == (a == 1), "type and shape survive");
			assert(back.count() == (a == 1 ? 2 : 1), "element count");
		}
	}
}

fn void errors_variant() @test
{
	assert(fails_with("86 FF FF FF 7F", VARIANT, BAD_LENGTH));                               // M51: 2^31-1 elements, no data
	assert(fails_with("86 FD FF FF FF", VARIANT, BAD_LENGTH));                               // M52
	assert(fails_with("1A", VARIANT, BAD_ENCODING));                                         // M53: type id 26
	assert(fails_with("3F", VARIANT, BAD_ENCODING));                                         // M54: type id 63
	assert(fails_with("80 00 00 00 00", VARIANT, BAD_ENCODING));                             // M55: array flag with Null type
	assert(fails_with("46 2A 00 00 00 01 00 00 00 01 00 00 00", VARIANT, BAD_ENCODING));     // M56: dims bit without array bit
	assert(fails_with("C6 04 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 02 00 00 00 03 00 00 00 03 00 00 00",
		VARIANT, BAD_LENGTH));                                                               // M57: 4 elements, dims 3 x 3
	assert(fails_with("C6 01 00 00 00 00 00 00 00 02 00 00 00 FF FF FF 7F FF FF FF 7F", VARIANT, BAD_LENGTH));   // M58
	assert(fails_with("C6 01 00 00 00 00 00 00 00 01 00 00 00 FF FF FF FF", VARIANT, BAD_LENGTH));               // M59
	assert(fails_with("C6 01 00 00 00 00 00 00 00 FF FF FF 7F", VARIANT, BAD_LENGTH));                           // M60
	assert(fails_with("C6 01 00 00 00 00 00 00 00 00 00 00 00", VARIANT, BAD_LENGTH));       // dimension count 0
	assert(fails_with("18 00", VARIANT, BAD_ENCODING));                                      // M62: scalar Variant in a Variant
	assert(fails_with("", VARIANT, TRUNCATED));
	assert(fails_with("06 2A", VARIANT, TRUNCATED));
}

fn void errors_variant_encoder() @test
{
	Variant empty_arr = { .type = EMPTY, .is_array = true };
	Encoder e = encoder_sizer();
	assert(@fails(e.put_variant(empty_arr), BAD_ENCODING));
	Variant scalar_in_variant = { .type = VARIANT };
	assert(@fails(e.put_variant(scalar_in_variant), BAD_ENCODING));
	int[4] four = { 1, 2, 3, 4 };
	uint[2] bad_dims = { 3, 3 };
	Variant m = arr_i32(&four);
	m.dims = &bad_dims;
	assert(@fails(e.put_variant(m), BAD_LENGTH));
	uint[1] some = { 4 };
	Variant not_array = variant_i32(1);
	not_array.dims = &some;
	assert(@fails(e.put_variant(not_array), BAD_ENCODING));
}

fn void prefix_sweep_variant_arrays_of_text() @test
{
	check_vector("8C 02 00 00 00 01 00 00 00 61 FF FF FF FF", VARIANT);        // String[] {"a", null}
}
