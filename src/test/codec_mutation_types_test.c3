module opcua;

// Fixed-seed mutation of every structured vector: a value or a fault, never a crash, and the allocation high-water mark
// stays small (a length claim must not buy memory).

const Vector[*] TYPE_VECTORS = {
	{ "00 00 00 00 00 00 00 00", DATETIME }, { "00 80 3E D5 DE B1 9D 01", DATETIME }, { "FF FF FF FF FF FF FF 7F", DATETIME },
	{ "02 00 03 00 00 00 46 6F 6F", QNAME }, { "00 00 FF FF FF FF", QNAME },
	{ "03 02 00 00 00 65 6E 02 00 00 00 48 69", LTEXT }, { "02 02 00 00 00 48 69", LTEXT }, { "00", LTEXT },
	{ "C0 48 05 00 00 00 75 72 6E 3A 61 05 00 00 00", XNODEID }, { "80 48 05 00 00 00 75 72 6E 3A 61", XNODEID },
	{ "40 48 07 00 00 00", XNODEID }, { "00 48", XNODEID },
	{ "00", VARIANT }, { "01 01", VARIANT }, { "06 2A 00 00 00", VARIANT }, { "0C 03 00 00 00 61 62 63", VARIANT },
	{ "0B 00 00 00 00 00 00 F0 3F", VARIANT }, { "86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00", VARIANT },
	{ "86 00 00 00 00", VARIANT }, { "86 FF FF FF FF", VARIANT },
	{ "C6 06 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 02 00 00 00 02 00 00 00 03 00 00 00", VARIANT },
	{ "98 02 00 00 00 06 2A 00 00 00 00", VARIANT }, { "15 03 02 00 00 00 65 6E 02 00 00 00 48 69", VARIANT },
	{ "0D 00 80 3E D5 DE B1 9D 01", VARIANT }, { "0F 02 00 00 00 AA BB", VARIANT }, { "13 00 00 34 80", VARIANT },
	{ "8C 02 00 00 00 01 00 00 00 61 FF FF FF FF", VARIANT },
	{ "00", DATAVALUE }, { "01 06 2A 00 00 00", DATAVALUE }, { "03 06 2A 00 00 00 00 00 34 80", DATAVALUE },
	{ "02 00 00 34 80", DATAVALUE }, { "0D 06 2A 00 00 00 00 80 3E D5 DE B1 9D 01 00 80 3E D5 DE B1 9D 01", DATAVALUE },
	{ "31 06 2A 00 00 00 05 00 07 00", DATAVALUE }, { "01 17 01 06 01 00 00 00", DATAVALUE },
	{ "00 00 00", EXTOBJ }, { "01 01 88 13 01 03 00 00 00 AA BB CC", EXTOBJ }, { "01 01 88 13 02 04 00 00 00 3C 61 2F 3E", EXTOBJ },
	{ "01 01 88 13 01 FF FF FF FF", EXTOBJ },
	{ "00", DIAG }, { "01 05 00 00 00", DIAG }, { "10 02 00 00 00 68 69", DIAG }, { "20 00 00 34 80", DIAG },
	{ "40 20 00 00 34 80", DIAG }, { "1F 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 01 00 00 00 41", DIAG },
};

const int TYPE_ITERATIONS = 1000;

fn void mutation_types_decoders() @test
{
	sz cap = 4 << 20;
	char[] store = alloc::alloc_array(mem, char, cap);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	arena.init(store);
	Rng rng = { 0xD1B54A32D192ED03 };
	sz high_water = 0;
	foreach (v : TYPE_VECTORS)
	{
		char[] original = unhex(v.hex);
		for (int it = 0; it < TYPE_ITERATIONS; it++)
		{
			char[] data = alloc::alloc_array(tmem, char, original.len);
			mem::copy(data.ptr, original.ptr, original.len);
			int flips = 1 + (int)(rng.next() % 3u);
			for (int f = 0; f < flips; f++)
			{
				sz at = (sz)(rng.next() % (ulong)original.len);
				data[at] = (char)rng.next();
			}
			arena.clear();
			Decoder d = decoder(data, &arena);
			(void)decode_kind(&d, v.kind);
			if (arena.used > high_water) high_water = arena.used;
			assert(d.depth == 0, "depth is restored");
		}
	}
	assert(high_water < 64 * 1024, "allocation stays proportional to the input");
}

fn void mutation_types_hostile_limits() @test
{
	sz cap = 4 << 20;
	char[] store = alloc::alloc_array(mem, char, cap);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	arena.init(store);
	Limits l = default_limits();
	l.max_string_length = uint::max;
	l.max_bytestring_length = uint::max;
	l.max_array_length = uint::max;
	l.max_matrix_elements = uint::max;
	l.max_depth = 100000;
	Rng rng = { 0x94D049BB133111EB };
	foreach (v : TYPE_VECTORS)
	{
		char[] original = unhex(v.hex);
		for (int it = 0; it < TYPE_ITERATIONS; it++)
		{
			char[] data = alloc::alloc_array(tmem, char, original.len);
			mem::copy(data.ptr, original.ptr, original.len);
			for (sz f = 0; f < original.len; f++)
			{
				if (rng.next() % 4u == 0) data[f] = (char)rng.next();
			}
			arena.clear();
			Decoder d = decoder(data, &arena, l);
			(void)decode_kind(&d, v.kind);
			assert(arena.used < 64 * 1024, "a length claim never buys memory");
		}
	}
}
