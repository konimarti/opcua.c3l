module opcua;

// Bounds and allocation behaviour of the small codec helpers.

fn void bounds_patch_u32_rejects_bad_positions() @test
{
	char[16] store;
	ByteBuf b = { .data = &store, .len = 10 };
	assert(@fails(b.patch_u32(-1, 0x12345678), BUFFER_FULL));
	assert(@fails(b.patch_u32(sz::max - 1, 1), BUFFER_FULL));
	assert(@fails(b.patch_u32(7, 1), BUFFER_FULL));
	assert(@fails(b.patch_u32(10, 1), BUFFER_FULL));
	b.patch_u32(6, 0x04030201)!!;
	assert(store[6] == 1 && store[9] == 4);
	ByteBuf tiny = { .data = &store, .len = 2 };
	assert(@fails(tiny.patch_u32(0, 1), BUFFER_FULL));
}

fn void bounds_negative_array_len_is_rejected() @test
{
	Encoder e = encoder_sizer();
	assert(@fails(e.put_array_len(-2, false), BAD_LENGTH));
	assert(@fails(e.put_array_len(-1, false), BAD_LENGTH));
	e.put_array_len(-1, true)!!;
	e.put_array_len(3, false)!!;
}

fn void bounds_take_rejects_negative_length() @test
{
	Decoder d = dec("01 02 03 04");
	(void)d.take(2)!!;
	assert(@fails(d.take(-1), TRUNCATED));
	assert(d.remaining() == 2);
}

fn void bounds_array_len_zero_element_size() @test
{
	Decoder d = dec("05 00 00 00 AA");
	assert(@fails(d.get_array_len(0), TRUNCATED));
	Decoder ok = dec("01 00 00 00 AA");
	assert(ok.get_array_len(0)!! == 1);
}
