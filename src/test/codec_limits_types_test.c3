module opcua;

// Limits, depth and allocation behaviour of the structured decoders. Vectors M51-M61, M63, M77.

fn void limits_variant_default_array() @test
{
	sz n = 100000;
	int[] values = alloc::new_array(mem, int, n);
	defer alloc::free(mem, values.ptr);
	foreach (i, &x : values) *x = (int)i;
	ByteBuf b;
	b.init(mem);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_variant(variant_i32_array(values))!!;
	assert(b.len == 1 + 4 + n * 4);
	Decoder d = decoder(b.bytes(), mem);
	Variant v = d.get_variant()!!;
	defer alloc::free(mem, v.array.i32.ptr);
	assert(v.is_array && v.count() == n && v.array.i32[99999] == 99999 && v.array.i32[0] == 0);
	assert(d.remaining() == 0);
}

fn void limits_variant_array_over_limit() @test
{
	assert(fails_with("86 41 42 0F 00", VARIANT, BAD_LENGTH));           // 1_000_001 elements
	Decoder d = dec("00 CA 9A 3B");                                      // M77: 10^9 elements, 4 bytes of data
	assert(@fails(d.get_array_len(4), BAD_LENGTH));
	Limits l = default_limits();
	l.max_array_length = 2;
	Decoder small = decoder(unhex("86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00"), tmem, l);
	assert(@fails(small.get_variant(), BAD_LENGTH));
	Limits m = default_limits();
	m.max_matrix_elements = 4;
	Decoder mat = decoder(unhex("C6 06 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 02 00 00 00 02 00 00 00 03 00 00 00"), tmem, m);
	assert(@fails(mat.get_variant(), BAD_LENGTH));
}

fn void depth_variant_bomb() @test
{
	DString bomb = dstring::temp();
	for (int i = 0; i < 200; i++) bomb.append("98 01 00 00 00 ");        // M61
	assert(fails_with(bomb.str_view(), VARIANT, DEPTH_EXCEEDED));
	DString ok = dstring::temp();
	for (int i = 0; i < 31; i++) ok.append("98 01 00 00 00 ");
	ok.append("00");
	assert(decodes_fully(ok.str_view(), VARIANT));                         // 32 levels
	DString over = dstring::temp();
	for (int i = 0; i < 32; i++) over.append("98 01 00 00 00 ");
	over.append("00");
	assert(fails_with(over.str_view(), VARIANT, DEPTH_EXCEEDED));          // 33 levels
	Limits l = default_limits();
	l.max_depth = 100;
	Decoder d = decoder(unhex(over.str_view()), tmem, l);                  // the limit is configurable
	assert(@fails(d.get_variant(), DEPTH_EXCEEDED) == false);
}

fn void depth_returns_to_zero() @test
{
	Decoder d = dec("06 01 00 00 00 06 02 00 00 00");
	(void)d.get_variant()!!;
	assert(d.depth == 0);
	(void)d.get_variant()!!;
	assert(d.depth == 0);
	Decoder f = dec("98 01 00 00 00 1A");
	assert(@fails(f.get_variant(), BAD_ENCODING));
	assert(f.depth == 0, "depth is restored when decoding fails");
}

fn void no_alloc_on_bad_variant() @test
{
	char[256] store;
	ArenaAllocator arena;
	arena.init(&store);
	foreach (String hex : { "86 FF FF FF 7F", "86 FD FF FF FF", "1A", "3F", "80 00 00 00 00", "46 2A 00 00 00 01 00 00 00 01 00 00 00", "18 00" })
	{
		Decoder d = decoder(unhex(hex), &arena);
		if (try v = d.get_variant()) unreachable("must fail");
		assert(arena.used == 0, "nothing allocated for a rejected Variant header");
	}
	Decoder big = decoder(unhex("86 FF FF FF 7F"), &arena);
	Limits l = default_limits();
	l.max_array_length = uint::max;
	big.limits = l;
	assert(@fails(big.get_variant(), TRUNCATED));                           // size check before allocation
	assert(arena.used == 0);
}
