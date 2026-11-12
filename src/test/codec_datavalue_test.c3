module opcua;

// DataValue (OPC 10000-6 5.2.2.17). Vectors D1-D6, M74-M76 plus extras. There is no stored mask: the encoder derives the
// presence bits from the fields (value iff has_value, status iff != 0, timestamps iff != 0, picoseconds iff != 0).

fn void fixtures_datavalue() @test
{
	assert(enc_dv({}) == unhex("00"));                                                   // D1
	check_vector("00", DATAVALUE);
	DataValue d2 = { .value = variant_i32(42), .has_value = true };
	assert(enc_dv(d2) == unhex("01 06 2A 00 00 00"));                                    // D2
	check_vector("01 06 2A 00 00 00", DATAVALUE);
	DataValue d3 = { .value = variant_i32(42), .has_value = true, .status = (StatusCode)0x80340000 };
	assert(enc_dv(d3) == unhex("03 06 2A 00 00 00 00 00 34 80"));                        // D3
	check_vector("03 06 2A 00 00 00 00 00 34 80", DATAVALUE);
	DataValue d4 = { .status = (StatusCode)0x80340000 };
	assert(enc_dv(d4) == unhex("02 00 00 34 80"));                                       // D4: status only, no value
	check_vector("02 00 00 34 80", DATAVALUE);
	DataValue d5 = { .value = variant_i32(42), .has_value = true, .source_ts = (UaDateTime)116444736000000000, .server_ts = (UaDateTime)116444736000000000 };
	String h5 = "0D 06 2A 00 00 00 00 80 3E D5 DE B1 9D 01 00 80 3E D5 DE B1 9D 01";
	assert(enc_dv(d5) == unhex(h5));                                                     // D5
	check_vector(h5, DATAVALUE);
	DataValue d6 = { .value = variant_i32(42), .has_value = true, .source_pico = 5, .server_pico = 7 };
	assert(enc_dv(d6) == unhex("31 06 2A 00 00 00 05 00 07 00"));                        // D6
	check_vector("31 06 2A 00 00 00 05 00 07 00", DATAVALUE);
	DataValue dd = { .value = variant_f64(1.0), .has_value = true };
	assert(enc_dv(dd) == unhex("01 0B 00 00 00 00 00 00 F0 3F"));
}

fn void datavalue_decode_fields() @test
{
	Decoder d = dec("03 06 2A 00 00 00 00 00 34 80");
	DataValue v = d.get_data_value()!!;
	assert(v.has_value && v.value.type == INT32 && v.value.scalar.i32 == 42);
	assert((uint)v.status == 0x80340000 && (long)v.source_ts == 0 && v.source_pico == 0);
	Decoder s = dec("02 00 00 34 80");                                                   // status only: no value, distinct from a null Variant
	DataValue sv = s.get_data_value()!!;
	assert(!sv.has_value && sv.value.type == EMPTY && (uint)sv.status == 0x80340000);
	Decoder nv = dec("01 00");                                                           // a present but null Variant
	DataValue nvv = nv.get_data_value()!!;
	assert(nvv.has_value && nvv.value.type == EMPTY);
	assert(reencode("01 00", DATAVALUE) == unhex("01 00"));
}

// Presence comes from the fields: setting a status after the fact is enough, and explicit zeros are written in the short form.
fn void datavalue_presence_from_fields() @test
{
	DataValue v = { .value = variant_i32(1), .has_value = true };
	assert(enc_dv(v)[0] == 0x01);
	v.status = (StatusCode)0x40000000;
	assert(enc_dv(v)[0] == 0x03);
	v.source_ts = (UaDateTime)5;
	assert(enc_dv(v)[0] == 0x07);
	v.server_pico = 1;
	assert(enc_dv(v)[0] == 0x27);
	DataValue none = { .value = variant_i32(1) };                                          // has_value false: the value is not written
	assert(enc_dv(none) == unhex("00"));
	// non-canonical in, canonical out: an explicit Good status and zero timestamp decode and re-encode in the short form
	assert(decodes_fully("07 06 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", DATAVALUE));
	assert(reencode("07 06 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", DATAVALUE) == unhex("01 06 2A 00 00 00"));
}

fn void errors_datavalue() @test
{
	assert(fails_with("40", DATAVALUE, BAD_ENCODING));                                   // M74: reserved bit
	assert(fails_with("80", DATAVALUE, BAD_ENCODING));
	assert(fails_with("01", DATAVALUE, TRUNCATED));                                      // M75: value flagged but absent
	assert(fails_with("10 05", DATAVALUE, TRUNCATED));                                   // M76: picoseconds need 2 bytes
	assert(fails_with("02 00 00", DATAVALUE, TRUNCATED));
}

// A DataValue nested in a Variant nested in a DataValue ... is bounded by the depth limit (32 levels).
fn void datavalue_nesting_is_bounded() @test
{
	DString ok = dstring::temp();
	for (int i = 0; i < 15; i++) ok.append("01 17 ");          // DataValue with a value, the value is a DataValue
	ok.append("00");
	assert(decodes_fully(ok.str_view(), DATAVALUE));
	DString deep = dstring::temp();
	for (int i = 0; i < 16; i++) deep.append("01 17 ");
	deep.append("00");
	assert(fails_with(deep.str_view(), DATAVALUE, DEPTH_EXCEEDED));
	DataValue inner = { .value = variant_i32(1), .has_value = true };
	Variant v = { .type = DATAVALUE, .scalar.dv = &inner };
	DataValue outer = { .value = v, .has_value = true };
	assert(enc_dv(outer) == unhex("01 17 01 06 01 00 00 00"));
	check_vector("01 17 01 06 01 00 00 00", DATAVALUE);
}
