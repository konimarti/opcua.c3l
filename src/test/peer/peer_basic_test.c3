module opcua;
import std::io;
import std::thread;
import std::time;
import std::time::clock;

// Tests against a real server (the open62541 example server, SecurityPolicy None). Every test prints
// "SKIP: no peer configured" and passes when no peer is configured (see peer_support.c3).

fn void peer_endpoints() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	EndpointDescription[] eps = c.client.get_endpoints(&arena)!!;
	assert(eps.len > 0);
	assert(find_endpoint(eps, MessageSecurityMode.NONE, POLICY_NONE) != null, "an endpoint with mode None and policy None");
}

fn void peer_session_read_state() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	c.client.open_session()!!;
	DataValue v = c.client.read(&arena, nodeid_num(0, 2259))!!;
	assert(status_is_good(v.status) && v.has_value);
	assert(v.value.type == INT32 && v.value.scalar.i32 == 0, "ServerState Running");
	c.client.close()!!;
}

fn void peer_browse_objects() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	c.client.open_session()!!;
	BrowseResult b = c.client.browse(&arena, nodeid_num(0, 85))!!;
	bool found = false;
	foreach (r : b.references)
	{
		if (r.browse_name.name == "Server") found = true;
	}
	assert(found, "the Objects folder contains Server");
}

fn void peer_translate_server() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	c.client.open_session()!!;
	RelativePathElement[2] path = {
		{ .reference_type_id = nodeid_num(0, 35), .include_subtypes = true, .target_name = { .name = "Objects" } },
		{ .reference_type_id = nodeid_num(0, 35), .include_subtypes = true, .target_name = { .name = "Server" } },
	};
	BrowsePathResult r = c.client.translate(&arena, nodeid_num(0, 84), &path)!!;
	assert(status_is_good(r.status_code) && r.targets.len == 1);
	assert(nodeid_equals(r.targets[0].target_id.id, nodeid_num(0, 2253)));
}

fn void peer_username_session() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	if (pc.user.len == 0)
	{
		io::printn("SKIP: no user configured");
		return;
	}
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	// refused locally without the opt-in
	PeerConn* refused = peer_connect(&pc, peer_default_config())!!;
	assert(@fails(refused.client.open_session(identity_username(pc.user, pc.password)), SECURITY_UNSUPPORTED));
	refused.drop();
	Config cfg = peer_default_config();
	cfg.allow_cleartext_password = true;
	PeerConn* c = peer_connect(&pc, cfg)!!;
	defer c.drop();
	c.client.open_session(identity_username(pc.user, pc.password))!!;
	DataValue v = c.client.read(&arena, nodeid_num(0, 2259))!!;
	assert(status_is_good(v.status));
}

fn void peer_write_gate() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	NodeId node = peer_node(pc.node_int32);
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	c.client.open_session()!!;
	assert(@fails(c.client.write(&arena, node, variant_i32(7)), WRITE_NOT_ALLOWED), "refused by default");
	Config cfg = peer_default_config();
	cfg.allow_write = true;
	PeerConn* w = peer_connect(&pc, cfg)!!;
	defer w.drop();
	w.client.open_session()!!;
	DataValue before = w.client.read(&arena, node)!!;
	assert(w.client.write(&arena, node, variant_i32(7))!! == STATUS_GOOD);
	DataValue after = w.client.read(&arena, node)!!;
	assert(after.value.type == INT32 && after.value.scalar.i32 == 7, "the value reads back");
	if (before.has_value && before.value.type == INT32) (void)w.client.write(&arena, node, before.value);       // restore
}

fn void peer_call_add() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	NodeId object = peer_node(pc.method_object);
	NodeId method = peer_node(pc.method);
	bool string_method = pc.method_kind == "string";
	Variant[2] args = { variant_i32(2), variant_i32(3) };
	if (string_method) args[0] = variant_string("peer");
	Variant[] used = string_method ? args[:1] : args[:2];
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	c.client.open_session()!!;
	assert(@fails(c.client.call(&arena, object, method, used), WRITE_NOT_ALLOWED));
	Config cfg = peer_default_config();
	cfg.allow_write = true;
	PeerConn* w = peer_connect(&pc, cfg)!!;
	defer w.drop();
	w.client.open_session()!!;
	CallMethodResult r = w.client.call(&arena, object, method, used)!!;
	assert(status_is_good(r.status_code) && r.output_arguments.len == 1);
	if (string_method)
	{
		assert(r.output_arguments[0].type == STRING && r.output_arguments[0].scalar.str.len > 0);
	}
	else
	{
		assert(r.output_arguments[0].scalar.i32 == 5);
	}
}

fn void peer_browse_continuation_points() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	c.client.open_session()!!;
	BrowseResult all = c.client.browse(&arena, nodeid_num(0, 84))!!;
	BrowseResult paged = c.client.browse(&arena, nodeid_num(0, 84), BrowseDirection.FORWARD, 1)!!;
	assert(all.references.len >= 2, "the Root folder has several references");
	assert(paged.references.len == all.references.len, "one reference per page, all of them merged");
}

fn void peer_unknown_node_is_data() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	c.client.open_session()!!;
	DataValue v = c.client.read(&arena, nodeid_num(0, 999999))!!;
	assert(status_is_bad(v.status), "a Bad status as data, not a fault");
	assert(c.client.machine.state == State.ACTIVE);
}

// F-03: with service() the channel survives its lifetime; the read afterwards works.
fn void peer_idle_with_service() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	Config cfg = peer_default_config();
	cfg.channel_lifetime_ms = 4000;
	PeerConn* c = peer_connect(&pc, cfg)!!;
	defer c.drop();
	c.client.open_session()!!;
	ulong revised = c.client.machine.lifetime_ms;                         // the peer may revise the requested lifetime
	long wait_ms = (long)revised + 1000;
	Clock start = clock::now();
	while ((long)start.to_now() / 1_000_000 < wait_ms) c.client.service(time::ms(100))!!;
	peer_note(string::tformat("OBSERVED: idle with service(): revised lifetime %d ms, %d renewals, %d renew failures", revised, c.client.renewals, c.client.renew_failures));
	assert(c.client.renewals >= 1, "the channel was renewed while idle");
	DataValue v = c.client.read(&arena, nodeid_num(0, 2259))!!;
	assert(status_is_good(v.status));
}

// Without service() the overdue renewal goes out before the next request, or the call fails: the observed behaviour goes
// into QUIRKS.md; either outcome is acceptable here, a crash is not.
fn void peer_idle_without_service() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	Config cfg = peer_default_config();
	cfg.channel_lifetime_ms = 4000;
	PeerConn* c = peer_connect(&pc, cfg)!!;
	defer c.drop();
	c.client.open_session()!!;
	peer_note(string::tformat("OBSERVED: requested channel lifetime 4000 ms, revised %d ms", c.client.machine.lifetime_ms));
	long wait_ms = (long)c.client.machine.lifetime_ms + 1000;
	thread::sleep_ms((uint)wait_ms);
	DataValue? v = c.client.read(&arena, nodeid_num(0, 2259));
	if (catch err = v)
	{
		peer_note(string::tformat("OBSERVED: read after an idle period without service() failed with %s", err));
	}
	else
	{
		peer_note(string::tformat("OBSERVED: read after an idle period without service() succeeded (renewals %d, revised lifetime %d ms)", c.client.renewals, c.client.machine.lifetime_ms));
	}
}
