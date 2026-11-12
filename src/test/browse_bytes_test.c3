module opcua;

// The bytes a Client.browse merges are bounded as well: a few references with huge names are as bad as many small ones.

fn void browse_bytes_are_bounded() @test
{
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	// every reference carries about 2 x 300 characters of names (browse and display name) plus its fixed part
	ScriptTransport st;
	st.start();
	defer st.stop();
	st.name_length = 300;
	st.total_pages = 5;                                     // a continuation point is still held when the limit is hit
	Config cfg = client_config();
	cfg.limits.max_browse_bytes = 4 * 700 - 1;              // a reference counts 100 bytes plus its names: four are one byte too much
	Client* c = connect_script(&st, cfg);
	defer c.free();
	c.open_session()!!;
	assert(@fails(c.browse(&arena, nodeid_num(0, 85)), TOO_MANY_REFERENCES));
	assert(st.release_seen == 1, "the held continuation point is released");
	ScriptTransport ok;
	ok.start();
	defer ok.stop();
	ok.name_length = 300;
	ok.total_pages = 4;
	Config roomy = client_config();
	roomy.limits.max_browse_bytes = 4 * 1000;
	Client* d = connect_script(&ok, roomy);
	defer d.free();
	d.open_session()!!;
	assert(d.browse(&arena, nodeid_num(0, 85))!!.references.len == 4);
	// the default limit is generous, and a hand-built Limits (0) means the default
	ScriptTransport zero;
	zero.start();
	defer zero.stop();
	zero.name_length = 300;
	Config z = client_config();
	z.limits.max_browse_bytes = 0;
	Client* e = connect_script(&zero, z);
	defer e.free();
	e.open_session()!!;
	assert(e.browse(&arena, nodeid_num(0, 85))!!.references.len == 2);
}
