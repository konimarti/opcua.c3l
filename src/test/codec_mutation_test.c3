module opcua;

// Smoke mutation test: fixed-seed random byte changes over every vector of this file. The decoder must return a value or a
// fault, never crash, and its allocations stay tiny (the inputs are tiny; a length claim must not buy memory).

struct Vector
{
	String hex;
	Kind kind;
}

const Vector[*] VECTORS = {
	{ "01", BOOL }, { "02", BOOL }, { "34 12", U16 }, { "FE FF FF FF", U32 }, { "78 56 34 12", U32 }, { "00 00 C0 3F", F32 },
	{ "00 00 00 00 00 00 F0 3F", F64 }, { "00 00 00 00 00 00 04 C0", F64 }, { "00 00 00 00 00 00 F0 7F", F64 },
	{ "01 00 00 00 00 00 F8 7F", F64 }, { "03 00 00 00 61 62 63", STRING }, { "FF FF FF FF", STRING }, { "00 00 00 00", STRING },
	{ "03 00 00 00 E6 B0 B4", STRING }, { "02 00 00 00 AA BB", BYTES }, { "FF FF FF FF", BYTES },
	{ "91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63", GUID }, { "00 00 00 00", U32 }, { "00 00 34 80", U32 },
	{ "00 48", NODEID }, { "00 00", NODEID }, { "01 01 E8 03", NODEID }, { "01 00 D2 08", NODEID },
	{ "02 2C 01 70 11 01 00", NODEID }, { "03 02 00 05 00 00 00 48 65 6C 6C 6F", NODEID },
	{ "03 01 00 06 00 00 00 48 6F 74 E6 B0 B4", NODEID },
	{ "04 02 00 91 2B 96 72 75 FA E6 4A 8D 28 B4 04 DC 7D AF 63", NODEID }, { "05 03 00 02 00 00 00 AA BB", NODEID },
	{ "02 00 00 05 00 00 00", NODEID }, { "03 00 00 FF FF FF FF", NODEID },
};

const int ITERATIONS = 500;

fn void mutation_smoke_decoders() @test
{
	sz cap = 1 << 20;
	char[] store = alloc::alloc_array(mem, char, cap);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	arena.init(store);
	Rng rng = { 0x9E3779B97F4A7C15 };
	sz high_water = 0;
	foreach (v : VECTORS)
	{
		char[] original = unhex(v.hex);
		for (int it = 0; it < ITERATIONS; it++)
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
			(void)decode_kind(&d, v.kind);           // a value or a fault: both are fine, a crash is not
			if (arena.used > high_water) high_water = arena.used;
			assert(arena.used < 4096, "allocation stays proportional to the input");
		}
	}
	assert(high_water < 4096);
}

// Truncations at every position of every vector, in a decoder with a hostile (maximum) limit set: still no allocation blow-up.
fn void mutation_smoke_hostile_limits() @test
{
	sz cap = 1 << 20;
	char[] store = alloc::alloc_array(mem, char, cap);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	arena.init(store);
	Limits l = default_limits();
	l.max_string_length = uint::max;
	l.max_bytestring_length = uint::max;
	l.max_array_length = uint::max;
	Rng rng = { 0x2545F4914F6CDD1D };
	foreach (v : VECTORS)
	{
		char[] original = unhex(v.hex);
		for (int it = 0; it < ITERATIONS; it++)
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
			assert(arena.used < 4096, "a length claim never buys memory");
		}
	}
}
