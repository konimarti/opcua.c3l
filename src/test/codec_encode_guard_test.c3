module opcua;

// Rejected output writes nothing; hostile values never overflow.

fn void guard_datetime_from_unix_ms_saturates() @test
{
	assert((long)datetime_from_unix_ms(long::max) == long::max);
	assert((long)datetime_from_unix_ms(long::max - UA_UNIX_EPOCH_MS) > 0);
	assert((long)datetime_from_unix_ms(long::max - UA_UNIX_EPOCH_MS + 1) == long::max);
	assert((long)datetime_from_unix_ms(long::min) == 0);
	assert((long)datetime_from_unix_ms(0) == 116444736000000000);
}

fn void guard_bad_matrix_writes_nothing() @test
{
	ByteBuf b;
	b.init(tmem);
	Encoder e = encoder(&b);
	int[4] four = { 1, 2, 3, 4 };
	uint[2] bad = { 3, 3 };
	Variant m = arr_i32(&four);
	m.dims = &bad;
	assert(@fails(e.put_variant(m), BAD_LENGTH));
	assert(b.len == 0, "no partial output");
	uint[2] huge = { 0x10000, 0x10000 };
	m.dims = &huge;
	assert(@fails(e.put_variant(m), BAD_LENGTH));
	assert(b.len == 0);
	uint[2] good = { 2, 2 };
	m.dims = &good;
	e.put_variant(m)!!;
	assert(b.len > 0);
}

fn void guard_null_scalar_pointers_are_faults() @test
{
	Encoder e = encoder_sizer();
	foreach (BuiltIn t : { BuiltIn.NODEID, BuiltIn.EXPANDEDNODEID, BuiltIn.QUALIFIEDNAME, BuiltIn.LOCALIZEDTEXT, BuiltIn.EXTENSIONOBJECT, BuiltIn.DATAVALUE, BuiltIn.DIAGNOSTICINFO })
	{
		Variant v = { .type = t };
		assert(@fails(e.put_variant(v), BAD_ENCODING));
	}
}
