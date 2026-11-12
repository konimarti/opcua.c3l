module opcua;

// NodeId text form: braced GUIDs and allocation behaviour.

fn void nodeid_text_braced_guid() @test
{
	NodeId a = parse_nodeid("g={72962B91-FA75-4AE6-8D28-B404DC7DAF63}", tmem)!!;
	NodeId b = parse_nodeid("g=72962B91-FA75-4AE6-8D28-B404DC7DAF63", tmem)!!;
	assert(nodeid_equals(a, b));
	assert(a.kind == GUID && a.guid.d1 == 0x72962B91);
	assert(@fails(parse_nodeid("g={72962B91-FA75-4AE6-8D28-B404DC7DAF63", tmem), BAD_NODEID));
	assert(@fails(parse_nodeid("g=[72962B91-FA75-4AE6-8D28-B404DC7DAF63]", tmem), BAD_NODEID));
}

// The text form is built in one formatting call on the caller's allocator, so an arena or heap user has nothing extra to
// free: it uses exactly as much as one direct format call of the same result.
fn void nodeid_text_single_allocation() @test
{
	char[1024] store;
	ArenaAllocator arena;
	arena.init(&store);
	(void)string::format(&arena, "%s", "ns=12345;s=Hello");
	sz one = arena.used;
	arena.clear();
	String s = nodeid_to_string(nodeid_str(12345, "Hello"), &arena);
	assert(s == "ns=12345;s=Hello");
	assert(arena.used == one, "no intermediate buffers");
	arena.clear();
	(void)string::format(&arena, "%s", "ns=12345;b=AQIDBAUG");
	one = arena.used;
	arena.clear();
	String o = nodeid_to_string({ .ns = 12345, .kind = OPAQUE, .bytes = unhex("01 02 03 04 05 06") }, &arena);
	assert(o == "ns=12345;b=AQIDBAUG");
	assert(arena.used == one, "no intermediate buffers");
}
