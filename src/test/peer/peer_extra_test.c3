module opcua;
import std::io;
import std::os::posix;
import std::thread;
import std::time;
import std::time::clock;

// Multi-chunk transfer, renewals and the negative cases against a peer (see peer_support.c3). A test that cannot run says
// why: "SKIP: <reason>".

fn bool peer_skip_reason(String reason)
{
	io::printfn("SKIP: %s", reason);
	return true;
}

fn long elapsed_ms(Clock start) => (long)start.to_now() / 1_000_000;

// 100 000 Int32 elements need many chunks at a buffer size of 8192; the default limits are enough (nothing was raised).
fn void peer_multichunk_array() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	if (pc.node_array.len == 0)
	{
		peer_skip_reason("no OPCUA_NODE_ARRAY configured");
		return;
	}
	Config cfg = peer_default_config();
	cfg.allow_write = true;
	cfg.send_buffer_size = 8192;
	cfg.receive_buffer_size = 8192;
	cfg.ignore_server_request_limit = true;                 // asyncua announces 65536 but takes larger requests (QUIRKS.md)
	assert(cfg.limits.max_array_length == 1_000_000 && cfg.limits.max_message_size == 16 << 20, "no limit was raised");
	DynamicArenaAllocator arena;
	arena.init(mem, 1 << 20);
	defer arena.free();
	NodeId node = peer_node(pc.node_array);
	PeerConn* c = peer_connect(&pc, cfg)!!;
	defer c.drop();
	c.client.open_session()!!;
	int[] data = alloc::alloc_array(mem, int, 100000);
	defer alloc::free(mem, data.ptr);
	foreach (i, &x : data) *x = (int)(i * 3 + 1);
	DataValue before = c.client.read(&arena, node)!!;
	assert(c.client.write(&arena, node, variant_i32_array(data))!! == STATUS_GOOD);
	DataValue back = c.client.read(&arena, node)!!;
	assert(back.has_value && back.value.is_array && back.value.type == INT32 && back.value.count() == 100000);
	assert(back.value.array.i32 == data, "equal after the read back");
	assert(c.client.machine.writer.max_chunk_size <= 8192, "the request really was split into small chunks");
	if (before.has_value && before.value.is_array) (void)c.client.write(&arena, node, before.value);
}

// F-05: with a 4 s lifetime, ten seconds of service() renew the channel at least twice and nothing fails.
fn void peer_renewal_for_ten_seconds() @test
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
	if (c.client.machine.lifetime_ms > 6000)
	{
		peer_skip_reason("the peer does not honour a short channel lifetime");
		return;
	}
	c.client.open_session()!!;
	Clock start = clock::now();
	int reads = 0;
	while (elapsed_ms(start) < 10000)
	{
		c.client.service(time::ms(250))!!;
		if (reads < 100 && elapsed_ms(start) > (long)reads * 1000)
		{
			assert(status_is_good(c.client.read(&arena, nodeid_num(0, 2259))!!.status));
			reads++;
		}
	}
	peer_note(string::tformat("OBSERVED: 10 s with a %d ms channel lifetime: %d renewals, %d renew failures, %d reads", c.client.machine.lifetime_ms, c.client.renewals, c.client.renew_failures, reads));
	assert(c.client.renewals >= 2 && c.client.renew_failures == 0);
	assert(c.client.machine.state == State.ACTIVE);
}

// F-05: the peer is stopped (SIGSTOP) for part of one renewal interval: CHANNEL_RENEW_FAILED, then recovery after SIGCONT.
fn void peer_renewal_survives_a_paused_peer() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	String pid_text = pc.peer_pid;
	if (pid_text.len == 0)
	{
		peer_skip_reason("no OPCUA_PEER_PID configured (the harness script writes it)");
		return;
	}
	int pid = string::to_integer{int}(pid_text) ?? 0;
	if (pid <= 1)
	{
		peer_skip_reason("OPCUA_PEER_PID is not a process id");
		return;
	}
	$if !env::POSIX:
		peer_skip_reason("pausing a process needs POSIX signals");
		return;
	$else
		Config cfg = peer_default_config();
		cfg.channel_lifetime_ms = 4000;
		cfg.request_timeout_ms = 300;
		PeerConn* c = peer_connect(&pc, cfg)!!;
		defer c.drop();
		if (c.client.machine.lifetime_ms != 4000)
		{
			peer_skip_reason("the peer does not honour a 4000 ms channel lifetime");
			return;
		}
		Clock start = clock::now();
		bool stopped = false;
		bool resumed = false;
		// the renewal is due at 3000 ms and the old token ends at 4000 ms: stop the peer at 2800 ms, resume it at 3700 ms
		while (elapsed_ms(start) < 3990 && c.client.renewals == 0)
		{
			long t = elapsed_ms(start);
			if (!stopped && t >= 2800)
			{
				posix::kill(pid, 19);                   // SIGSTOP
				stopped = true;
			}
			if (stopped && !resumed && t >= 3700)
			{
				posix::kill(pid, 18);                   // SIGCONT
				resumed = true;
			}
			if (catch err = c.client.service(time::ms(20)))
			{
				if (stopped && !resumed) posix::kill(pid, 18);
				peer_note(string::tformat("OBSERVED: paused peer: service() failed with %s at %d ms", err, t));
				assert(false, "the channel failed while the peer was paused");
			}
		}
		if (stopped && !resumed) posix::kill(pid, 18);
		peer_note(string::tformat("OBSERVED: paused peer: %d renew failures, %d renewals at %d ms", c.client.renew_failures, c.client.renewals, elapsed_ms(start)));
		assert(c.client.renew_failures >= 1, "CHANNEL_RENEW_FAILED while the peer was paused");
		assert(c.client.renewals >= 1 && c.client.machine.state == State.CHANNEL_OPEN, "recovered after SIGCONT");
	$endif
}

fn void peer_negative_cases() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	// a closed port: the connect fails at once
	EndpointUrl u = parse_endpoint_url(pc.url)!!;
	Clock start = clock::now();
	assert(!@ok(tcp_connect(u.host, 1, time::sec(2))), "nothing listens on port 1");
	assert(elapsed_ms(start) < 2500, "the connect fault comes within the timeout");
	PeerConn* c = peer_connect(&pc, peer_default_config())!!;
	defer c.drop();
	c.client.open_session()!!;
	// an empty node list is refused locally and nothing is sent
	ReadValueId[] none;
	uint before = c.client.machine.next_handle;
	assert(@fails(c.client.read_many(&arena, none), EMPTY_REQUEST));
	assert(c.client.machine.pending_count == 0 && c.client.machine.pending_output().len == 0 && c.client.machine.next_handle == before);
	// write and call without the flags
	assert(@fails(c.client.write(&arena, nodeid_num(0, 2259), variant_i32(1)), WRITE_NOT_ALLOWED));
	Variant[1] args = { variant_i32(1) };
	assert(@fails(c.client.call(&arena, nodeid_num(0, 85), nodeid_num(0, 1), &args), WRITE_NOT_ALLOWED));
	// an unknown node is a Bad status as data
	DataValue v = c.client.read(&arena, nodeid_num(0, 999999))!!;
	assert(status_is_bad(v.status));
	// a bad continuation point is a Bad status as data
	char[][1] points = { unhex("DE AD BE EF") };
	Response? r = c.client.browse_next(&arena, &points, false);
	if (catch err = r)
	{
		// some servers (asyncua: BrowseNext is not in its permission rules) answer the whole service with a fault
		assert(err == SERVICE_FAULT && status_is_bad(c.client.last_status));
		peer_note(string::tformat("OBSERVED: bad continuation point: ServiceFault %s", status_name(c.client.last_status)));
	}
	else
	{
		assert(r.browse_results.len == 1 && status_is_bad(r.browse_results[0].status_code), "BadContinuationPointInvalid as data");
		peer_note(string::tformat("OBSERVED: bad continuation point: result status %s", status_name(r.browse_results[0].status_code)));
	}
	assert(c.client.machine.state == State.ACTIVE);
}

// A call with the wrong argument types is answered per call (a Bad status in the result), not with a fault.
fn void peer_call_wrong_argument_types() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	if (pc.method_kind == "string")
	{
		peer_skip_reason("the peer's method takes a String: no Int32 method to misuse");
		return;
	}
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	Config cfg = peer_default_config();
	cfg.allow_write = true;
	PeerConn* c = peer_connect(&pc, cfg)!!;
	defer c.drop();
	c.client.open_session()!!;
	Variant[2] bad = { variant_string("a"), variant_string("b") };
	CallMethodResult r = c.client.call(&arena, peer_node(pc.method_object), peer_node(pc.method), &bad)!!;
	assert(status_is_bad(r.status_code) || r.input_argument_results.len > 0, "the wrong types are reported in the result");
	Variant[1] few = { variant_i32(1) };
	CallMethodResult f = c.client.call(&arena, peer_node(pc.method_object), peer_node(pc.method), &few)!!;
	assert(status_is_bad(f.status_code), "too few arguments");
	assert(c.client.machine.state == State.ACTIVE);
}

// The endpoint path is part of the HEL: a wrong path is either accepted or refused by the server; both are fine, a hang is not.
fn void peer_wrong_endpoint_path() @test
{
	PeerConfig pc = peer_config();
	if (peer_skip(&pc)) return;
	EndpointUrl u = parse_endpoint_url(pc.url)!!;
	String wrong = string::tformat("opc.tcp://%s:%d/no/such/path", u.host, u.port);
	TcpTransport tcp = tcp_connect(u.host, u.port)!!;
	Transport t = &tcp;
	Clock start = clock::now();
	Client*? c = client_connect(mem, t, wrong, peer_default_config());
	if (catch err = c)
	{
		peer_note(string::tformat("OBSERVED: wrong endpoint path: connect failed with %s", err));
	}
	else
	{
		peer_note("OBSERVED: wrong endpoint path: the server accepted the connection");
		(void)c.close();
		c.free();
	}
	assert(elapsed_ms(start) < 12000, "no hang");
}
