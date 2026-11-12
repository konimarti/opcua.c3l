module opcua;
import std::time;
import std::time::clock;
import std::thread;
import std::net;
import std::net::tcp;

// The blocking Client over a scripted transport: the whole stack without a socket and without a peer.

fn Config client_config()
{
	Config c = default_config();
	c.request_timeout_ms = 500;
	c.nonce_seed = 7;
	return c;
}

fn Client* connect_script(ScriptTransport* st, Config c = client_config())
{
	Transport t = st;
	return client_connect(mem, t, URL, c)!!;
}

fn void client_connect_and_close() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	assert(c.machine.state == State.CHANNEL_OPEN && c.machine.channel_id == 7);
	c.open_session()!!;
	assert(c.machine.state == State.ACTIVE);
	c.close()!!;
	assert(st.close_seen && st.closed, "CloseSecureChannel was sent and the transport closed");
	assert(c.machine.state == State.CLOSED);
	c.close()!!;                                                                           // twice is fine
	assert(@fails(c.get_endpoints(tmem), NOT_CONNECTED));
}

fn void client_read_browse_and_discovery() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	EndpointDescription[] eps = c.get_endpoints(&arena)!!;                                 // without a session
	assert(eps.len == 3);
	c.open_session()!!;
	DataValue v = c.read(&arena, nodeid_num(0, 2259))!!;
	assert(v.has_value && v.value.scalar.i32 == 42);
	BrowseResult b = c.browse(&arena, nodeid_num(0, 85))!!;
	assert(b.references.len == 2 && b.references[0].browse_name.name == "a" && b.references[1].browse_name.name == "b", "the pages are merged");
	assert(!status_is_bad(b.status_code) && bytes_is_null(b.continuation_point));
	assert(st.release_seen == 0);
	c.close()!!;
}

fn void client_write_and_call_need_the_flag() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	uint before = st.requests_seen;
	assert(@fails(c.write(&arena, nodeid_num(2, 1), variant_i32(7)), WRITE_NOT_ALLOWED));
	Variant[1] args = { variant_i32(1) };
	assert(@fails(c.call(&arena, nodeid_num(2, 1), nodeid_num(2, 2), &args), WRITE_NOT_ALLOWED));
	assert(st.requests_seen == before, "nothing was sent");
	c.close()!!;
	ScriptTransport st2;
	st2.start();
	defer st2.stop();
	Config cfg = client_config();
	cfg.allow_write = true;
	Client* w = connect_script(&st2, cfg);
	defer w.free();
	w.open_session()!!;
	assert(w.write(&arena, nodeid_num(2, 1), variant_i32(7))!! == STATUS_GOOD);
	assert(w.call(&arena, nodeid_num(2, 1), nodeid_num(2, 2), &args)!!.status_code == STATUS_GOOD);
	w.close()!!;
}

fn void client_service_fault_sets_last_status() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	st.fail_browse_next = true;
	assert(@fails(c.browse(&arena, nodeid_num(0, 85)), SERVICE_FAULT));
	assert((uint)c.last_status == 0x80010000, "the status of the fault is kept");
	assert(st.release_seen == 1, "the continuation point is released best-effort");
	assert(c.machine.state == State.ACTIVE, "a ServiceFault does not end the session");
}

fn void client_timeout_comes_from_the_machine() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	st.silent = true;
	assert(@fails(c.read(&arena, nodeid_num(0, 2259)), TIMEOUT));
	assert(c.machine.state == State.ACTIVE);
}

fn void client_peer_hangs_up() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	st.silent = true;
	st.eof_when_empty = true;
	assert(@fails(c.read(&arena, nodeid_num(0, 2259)), CLOSED));
	assert(c.machine.state == State.FAILED);
	assert(@fails(c.read(&arena, nodeid_num(0, 2259)), CLOSED), "a failed client keeps reporting the fault");
}

fn void client_handshake_failures() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	st.silent = true;
	Config c = client_config();
	c.handshake_timeout_ms = 300;
	Transport t = &st;
	assert(@fails(client_connect(mem, t, URL, c), TIMEOUT));
	ScriptTransport gone;
	gone.start();
	defer gone.stop();
	gone.silent = true;
	gone.eof_when_empty = true;
	Transport g = &gone;
	assert(@fails(client_connect(mem, g, URL, client_config()), CLOSED));
}

// The idle program duty: service() runs the renewal that is due, and next_deadline() says when.
fn void client_service_runs_the_renewal() @test
{
	ScriptTransport st;
	st.start(2000);                                                                         // the shortest lifetime the machine accepts
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	Duration d;
	assert(c.next_deadline(&d) && d.to_ms() > 1000 && d.to_ms() <= 1500, "75% of 2000 ms");
	Clock start = clock::now();
	while (c.renewals == 0 && (long)start.to_now() / 1_000_000 < 4000)
	{
		c.service(time::ms(100))!!;
	}
	assert(c.renewals == 1 && st.renewals_seen == 1, "the renewal went out and was answered");
	assert(c.machine.token_id == 2 && c.machine.state == State.CHANNEL_OPEN);
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	assert(c.read(&arena, nodeid_num(0, 2259))!!.has_value);
	c.close()!!;
}

// Without service() an overdue renewal goes out before the next request (the call starts with handle_timeout).
fn void client_overdue_renewal_goes_out_first() @test
{
	ScriptTransport st;
	st.start(2000);
	defer st.stop();
	Client* c = connect_script(&st);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	thread::sleep_ms(1700);                                                                 // past 75% of the lifetime, no service() in between
	DataValue v = c.read(&arena, nodeid_num(0, 2259))!!;
	assert(v.has_value);
	assert(st.renewals_seen >= 1, "the renewal was queued before the request");
	c.close()!!;
}

// ---------- the client over a real socket: the scripted server runs in a thread behind a loopback listener ----------
struct LoopServer
{
	TcpServerSocket listener;
	ScriptTransport script;
	int rounds;
}

fn int loop_server_main(void* arg)
{
	@pool_init(mem, 1 << 16)
	{
		loop_server_run((LoopServer*)arg);
	};
	return 0;
}

fn void loop_server_run(LoopServer* ls)
{
	TcpSocket conn = tcp::accept(&ls.listener)!!;
	defer (void)conn.close();
	char[4096] buf;
	Clock start = clock::now();
	while ((long)start.to_now() / 1_000_000 < 15000)
	{
		Poll[1] p = { { conn.sock, PollSubscribe.READ, {} } };
		ulong? ready = net::poll_ms(&p, 100);
		if (catch err = ready) break;
		if (ready == 0) continue;
		sz? n = conn.read(&buf);
		if (catch err = n) break;
		if (n == 0) break;
		ls.rounds++;
		if (catch err = ls.script.write(buf[:n], time::sec(1))) break;
		if (ls.script.inbox.len > 0)
		{
			if (catch err = conn.write(ls.script.inbox.bytes())) break;
			ls.script.inbox.clear();
		}
	}
}

fn void client_over_a_real_socket() @test
{
	LoopServer ls;
	ls.script.start();
	defer ls.script.stop();
	ls.listener = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)ls.listener.close();
	ushort port = ls.listener.local_port()!!;
	Thread th;
	th.create(&loop_server_main, &ls)!!;
	TcpTransport tcp = tcp_connect("127.0.0.1", port)!!;
	Transport t = &tcp;
	String url = string::tformat("opc.tcp://127.0.0.1:%d", port);
	Client* c = client_connect(mem, t, url, client_config())!!;
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	DataValue v = c.read(&arena, nodeid_num(0, 2259))!!;
	assert(v.has_value && v.value.scalar.i32 == 42);
	BrowseResult b = c.browse(&arena, nodeid_num(0, 85))!!;
	assert(b.references.len == 2);
	c.close()!!;
	c.free();
	th.join()!!;
	assert(ls.script.close_seen && ls.rounds >= 4);
}
