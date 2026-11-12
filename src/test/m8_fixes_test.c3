module opcua;

// Zero limits mean the defaults; the frame tracer skips an oversized frame instead of mis-parsing its rest.

fn void m8fix_zero_browse_limits_mean_the_defaults() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Config cfg = client_config();
	cfg.limits.max_browse_pages = 0;
	cfg.limits.max_browse_references = 0;
	Client* c = connect_script(&st, cfg);
	defer c.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	c.open_session()!!;
	assert(c.browse(&arena, nodeid_num(0, 85))!!.references.len == 2, "an ordinary two-page browse works with hand-built limits");
}

fn void m8fix_outbound_tracer_uses_the_send_buffer() @test
{
	ScriptTransport st;
	st.start();
	defer st.stop();
	Config cfg = client_config();
	cfg.send_buffer_size = 65536;
	cfg.receive_buffer_size = 8192;
	Client* c = connect_script(&st, cfg);
	defer c.free();
	assert(c.trace_out.max_frame == 65536 && c.trace_in.max_frame == 8192);
}

fn void m8fix_tracer_skips_an_oversized_frame() @test
{
	FrameTracer t;
	t.init(mem, 100);
	defer t.free();
	ByteBuf out;
	out.init(tmem);
	// a 1000 byte frame whose bytes arrive in pieces, then a normal frame
	char[] big = alloc::alloc_array(tmem, char, 1000);
	big[0] = 'M';
	big[1] = 'S';
	big[2] = 'G';
	big[3] = 'F';
	big[4] = 0xE8;
	big[5] = 0x03;
	big[6] = 0;
	big[7] = 0;
	foreach (i, &b : big)
	{
		if (i >= 8) *b = 'M';                                                                // bytes that look like a frame start
	}
	t.feed(big[:300], &out);
	t.feed(big[300:400], &out);
	t.feed(big[700..], &out);
	t.feed(unhex(B2_ACK), &out);
	String text = (String)out.bytes();
	sz lines = 0;
	foreach (c : text)
	{
		if (c == '\n') lines++;
	}
	assert(lines == 1 && text.contains("ACK F size=28"), "only the valid frame is traced, nothing is mistaken for a frame start");
}
