module opcua;
import std::time;

// Faults of the transport reach the machine, browsing is bounded, the trace is safe to print, the nonce comes from entropy.

fn void client_fixes_write_fault_fails_the_machine() @test
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
	st.closed = true;                                                                       // writes now fail with CLOSED
	assert(@fails(c.read(&arena, nodeid_num(0, 2259)), CLOSED));
	assert(c.machine.state == State.FAILED, "a failed write is reported to the machine");
	assert(@fails(c.read(&arena, nodeid_num(0, 2259)), CLOSED), "and the client stops sending");
	ScriptTransport slow;
	slow.start();
	defer slow.stop();
	Client* d = connect_script(&slow);
	defer d.free();
	d.open_session()!!;
	slow.write_times_out = true;                                                            // a chunk that may be partly sent cannot be repaired
	assert(@fails(d.read(&arena, nodeid_num(0, 2259)), TIMEOUT));
	assert(d.machine.state == State.FAILED && d.machine.failure == TIMEOUT);
}

fn void client_fixes_browse_is_bounded() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	st.endless_pages = true;
	Config cfg = client_config();
	cfg.limits.max_browse_pages = 5;
	Client* c = connect_script(&st, cfg);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	assert(@fails(c.browse(&arena, nodeid_num(0, 85)), TOO_MANY_PAGES));
	assert(st.release_seen == 1, "the continuation point that is held is released");
	assert(c.machine.state == State.ACTIVE);
	ScriptTransport st2;
	st2.start();
	defer st2.stop();
	st2.endless_pages = true;
	Config many = client_config();
	many.limits.max_browse_references = 3;
	Client* e = connect_script(&st2, many);
	defer e.free();
	e.open_session()!!;
	assert(@fails(e.browse(&arena, nodeid_num(0, 85)), TOO_MANY_PAGES));
	assert(st2.release_seen == 1);
	// the defaults are generous and a normal browse is not affected
	assert(default_limits().max_browse_pages == 1000 && default_limits().max_browse_references == 1_000_000);
	ScriptTransport ok;
	ok.start();
	defer ok.stop();
	Client* f = connect_script(&ok);
	defer f.free();
	f.open_session()!!;
	assert(f.browse(&arena, nodeid_num(0, 85))!!.references.len == 2);
}

fn void client_fixes_connect_failure_closes_the_transport() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	st.silent = true;
	Config c = client_config();
	c.handshake_timeout_ms = 200;
	Transport t = &st;
	assert(@fails(client_connect(mem, t, URL, c), TIMEOUT));
	assert(st.closed, "client_connect owns the transport, on failure as well");
}

fn void client_fixes_trace_prints_only_safe_text() @test
{
	// an OPN chunk whose policy URI holds a newline and an escape sequence
	String evil = "a\nb\x1B[31mc";
	ByteBuf b;
	b.init(tmem);
	Encoder e = encoder(&b);
	e.put_raw((char[])"OPNF")!!;
	e.put_u32(0)!!;
	e.put_u32(0)!!;
	e.put_string(evil)!!;
	e.put_bytestring(null_bytes())!!;
	e.put_bytestring(null_bytes())!!;
	e.put_u32(1)!!;
	e.put_u32(1)!!;
	b.patch_u32(4, (uint)b.len)!!;
	String out = traced(b.bytes());
	assert(!out.contains("\x1B") && out.contains("policy=a?b?[31mc"));
	sz lines = 0;
	foreach (c : out)
	{
		if (c == '\n') lines++;
	}
	assert(lines == 1, "one line per chunk");
	DString long_uri = dstring::temp();
	for (int i = 0; i < 400; i++) long_uri.append("u");
	ByteBuf l;
	l.init(tmem);
	Encoder le = encoder(&l);
	le.put_raw((char[])"OPNF")!!;
	le.put_u32(0)!!;
	le.put_u32(0)!!;
	le.put_string(long_uri.str_view())!!;
	le.put_bytestring(null_bytes())!!;
	le.put_bytestring(null_bytes())!!;
	le.put_u32(1)!!;
	le.put_u32(1)!!;
	l.patch_u32(4, (uint)l.len)!!;
	assert(traced(l.bytes()).len < 400, "the policy URI is cut");
}

fn void client_fixes_frame_tracer_is_bounded() @test
{
	FrameTracer t;
	t.init(mem, 100);
	defer t.free();
	ByteBuf out;
	out.init(tmem);
	t.feed(unhex("4D 53 47 46 E8 03 00 00 00 00 00 00"), &out);                              // announces 1000 bytes, the bound is 100
	assert(t.pending.len == 0 && out.len == 0, "an oversized frame is not buffered");
	t.feed(unhex(B2_ACK), &out);
	assert(((String)out.bytes()).contains("ACK F size=28"), "the next frame is traced");
}

fn void client_fixes_nonce_from_entropy_bytes() @test
{
	Config c = session_config();
	char[32] entropy;
	foreach (i, &x : entropy) *x = (char)(0xA0 + i);
	c.nonce_entropy = entropy;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_anonymous(), at(0))!!;
	Message cm = first_message(m.pending_output());
	String head = string::tformat("01 00 CD 01 %s %s %s 02 %s 01 00 00 00 %s %s %s %s %s %s 20 00 00 00",
		request_header_hex("00 00", 2, 1000), str_hex("urn:opcua.c3l:client"), str_hex("urn:opcua.c3l"), str_hex("opcua.c3l client"),
		NULL4, NULL4, NULL4, NULL4, str_hex(URL), str_hex("opcua.c3l session"));
	sz at = unhex(head).len;
	assert(cm.body[at:32] == (char[])entropy[:32], "the nonce is the entropy itself");
}
