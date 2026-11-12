module opcua;

// Limits and allocation behaviour of the decoder (DoS protection). Vectors M40-M43, M51-style array lengths.

fn Decoder arena_decoder(char[] input, ArenaAllocator* arena) => decoder(input, arena);

fn void limits_defaults_values() @test
{
	Limits l = default_limits();
	assert(l.max_string_length == 1 << 20);
	assert(l.max_bytestring_length == 16 << 20);
	assert(l.max_array_length == 1_000_000);
	assert(l.max_message_size == 16 << 20);
	assert(l.max_reassembly_bytes == l.max_message_size);
	assert(l.max_depth == 32 && l.max_chunk_count == 64);
}

// A 100 000 element array (real PLC data) is accepted by default, one above the limit is not.
fn void limits_defaults_array() @test
{
	sz n = 100000;
	char[] buf = alloc::alloc_array(mem, char, 4 + n * 4);
	defer alloc::free(mem, buf.ptr);
	mem::clear(buf.ptr, buf.len);
	buf[0] = 0xA0;                                    // 100000 = 0x000186A0
	buf[1] = 0x86;
	buf[2] = 0x01;
	Decoder d = decoder(buf, mem);
	assert(d.get_array_len(4)!! == 100000);
	Decoder over = dec("41 42 0F 00");               // 1_000_001
	assert(@fails(over.get_array_len(4), BAD_LENGTH));
	Decoder at = dec("40 42 0F 00 00 00 00 00");     // exactly 1_000_000: within the limit, but the data is missing
	assert(@fails(at.get_array_len(4), TRUNCATED));
}

fn void limits_defaults_bytestring() @test
{
	sz n = 5 * 1024 * 1024;                           // 5 MiB ByteString
	char[] buf = alloc::alloc_array(mem, char, 4 + n);
	defer alloc::free(mem, buf.ptr);
	mem::clear(buf.ptr, buf.len);
	buf[2] = 0x50;                                    // 0x00500000
	Decoder d = decoder(buf, mem);
	char[] bytes = d.get_bytestring()!!;
	defer alloc::free(mem, bytes.ptr);
	assert(bytes.len == n);
	Decoder over = dec("01 00 00 01");                // 16 MiB + 1: over the ByteString limit (checked before the data)
	assert(@fails(over.get_bytestring(), BAD_LENGTH));
	Decoder str = dec("01 00 10 00");                 // 1 MiB + 1: over the String limit
	assert(@fails(str.get_string(), BAD_LENGTH));
}

fn void limits_are_configurable() @test
{
	Limits l = default_limits();
	l.max_string_length = 4;
	Decoder d = decoder(unhex("05 00 00 00 41 42 43 44 45"), tmem, l);
	assert(@fails(d.get_string(), BAD_LENGTH));
	Decoder ok = decoder(unhex("04 00 00 00 41 42 43 44"), tmem, l);
	assert(ok.get_string()!! == "ABCD");
	l.max_array_length = 3;
	Decoder a = decoder(unhex("04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), tmem, l);
	assert(@fails(a.get_array_len(1), BAD_LENGTH));
}

fn void array_len_rules() @test
{
	Decoder n1 = dec("FF FF FF FF");
	assert(n1.get_array_len(4)!! == -1);                                          // null array
	Decoder z = dec("00 00 00 00");
	assert(z.get_array_len(4)!! == 0);                                            // empty array
	Decoder neg = dec("FE FF FF FF");
	assert(@fails(neg.get_array_len(4), BAD_LENGTH));
	Decoder ok = dec("02 00 00 00 01 02 03 04 05 06 07 08");
	assert(ok.get_array_len(4)!! == 2);
	Decoder short_data = dec("03 00 00 00 01 02 03 04 05 06 07 08");           // 3 * 4 > 8
	assert(@fails(short_data.get_array_len(4), TRUNCATED));
	Decoder huge = dec("FF FF FF 7F");                                           // INT32_MAX elements, no data
	assert(@fails(huge.get_array_len(1), BAD_LENGTH));
	Limits l = default_limits();
	l.max_array_length = uint::max;
	Decoder huge2 = decoder(unhex("FF FF FF 7F 00 00 00 00"), tmem, l);             // limit raised: the size check still bounds it
	assert(@fails(huge2.get_array_len(8), TRUNCATED));
	Decoder huge3 = decoder(unhex("FF FF FF 7F 00 00 00 00"), tmem, l);
	assert(@fails(huge3.get_array_len((sz)0x4000_0000_0000_0000), TRUNCATED));   // no overflow in the size check
	Encoder e = encoder_sizer();
	e.put_array_len(0, true)!!;
	e.put_array_len(3)!!;
	assert(e.written == 8);
	ByteBuf b;
	b.init(tmem);
	Encoder w = encoder(&b);
	w.put_array_len(0, true)!!;
	w.put_array_len(3)!!;
	assert(b.bytes() == unhex("FF FF FF FF 03 00 00 00"));
}

// A hostile length must not cost memory: the allocator is not touched before the checks pass.
fn void no_alloc_on_bad_length() @test
{
	char[64] store;
	ArenaAllocator arena;
	arena.init(&store);
	foreach (String hex : { "FF FF FF 7F", "64 00 00 00 41", "FE FF FF FF", "00 00 00 80", "0F 00 00 00 41" })
	{
		Decoder s = arena_decoder(unhex(hex), &arena);
		if (try v = s.get_string()) unreachable("must fail");
		Decoder b = arena_decoder(unhex(hex), &arena);
		if (try v = b.get_bytestring()) unreachable("must fail");
		assert(arena.used == 0, "nothing allocated for a rejected length");
	}
	Decoder bad_utf8 = arena_decoder(unhex("02 00 00 00 C3 28"), &arena);
	if (try v = bad_utf8.get_string()) unreachable("must fail");
	assert(arena.used == 0, "nothing allocated for invalid UTF-8");
	Decoder nid = arena_decoder(unhex("03 00 00 FF FF FF 7F"), &arena);
	if (try v = nid.get_nodeid()) unreachable("must fail");
	assert(arena.used == 0);
	Decoder arr = arena_decoder(unhex("FF FF FF 7F"), &arena);
	if (try v = arr.get_array_len(4)) unreachable("must fail");
	assert(arena.used == 0);
	Decoder good = arena_decoder(unhex("03 00 00 00 61 62 63"), &arena);
	assert(good.get_string()!! == "abc");
	assert(arena.used > 0 && arena.used < 64);
}
