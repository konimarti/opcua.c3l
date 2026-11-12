module opcua;

// Rejected input allocates nothing; rejected output writes nothing; hostile values never overflow.

fn void alloc_flagged_nodeid_in_plain_position() @test
{
	char[256] store;
	ArenaAllocator arena;
	arena.init(&store);
	foreach (String hex : { "83 01 00 05 00 00 00 48 65 6C 6C 6F", "C5 01 00 03 00 00 00 01 02 03" })
	{
		arena.clear();
		Decoder d = decoder(unhex(hex), &arena);
		assert(@fails(d.get_nodeid(), BAD_NODEID));
		assert(arena.used == 0, "nothing allocated for a flagged NodeId in a plain position");
	}
}

fn void alloc_failed_children_leave_no_container() @test
{
	char[512] store;
	ArenaAllocator arena;
	arena.init(&store);
	foreach (String hex : { "11 03 00 00 10 00 00 00", "12 83 00 00 00", "14 02 00 FF", "15 02 09 00 00 00", "16 01 00 2A 01 01 05 00 00 00 AA", "17 01 FF", "19 40 40" })
	{
		arena.clear();
		Decoder d = decoder(unhex(hex), &arena);
		if (try v = d.get_variant()) unreachable("must fail");
		assert(arena.used == 0, "the container is allocated after its content decoded");
	}
	arena.clear();
	Decoder diag = decoder(unhex("40 40"), &arena);
	assert(@fails(diag.get_diagnostic_info(), TRUNCATED));
	assert(arena.used == 0);
}
