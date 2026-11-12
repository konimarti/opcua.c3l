module opcua;

// Every field of Limits: a value of exactly the limit is accepted, one more is refused.

fn void limits_exact_string_and_bytestring() @test
{
	Limits l = default_limits();
	l.max_string_length = 5;
	l.max_bytestring_length = 4;
	Decoder ok = decoder(unhex("05 00 00 00 61 62 63 64 65"), tmem, l);
	assert(ok.get_string()!! == "abcde");
	Decoder over = decoder(unhex("06 00 00 00 61 62 63 64 65 66"), tmem, l);
	assert(@fails(over.get_string(), BAD_LENGTH));
	Decoder bok = decoder(unhex("04 00 00 00 01 02 03 04"), tmem, l);
	assert(bok.get_bytestring()!!.len == 4);
	Decoder bover = decoder(unhex("05 00 00 00 01 02 03 04 05"), tmem, l);
	assert(@fails(bover.get_bytestring(), BAD_LENGTH));
}

fn void limits_exact_array_and_matrix() @test
{
	Limits l = default_limits();
	l.max_array_length = 3;
	Decoder ok = decoder(unhex("86 03 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00"), tmem, l);
	assert(ok.get_variant()!!.count() == 3);
	Decoder over = decoder(unhex("86 04 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00"), tmem, l);
	assert(@fails(over.get_variant(), BAD_LENGTH));
	Limits m = default_limits();
	m.max_matrix_elements = 6;
	Decoder mok = decoder(unhex("C6 06 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 02 00 00 00 02 00 00 00 03 00 00 00"), tmem, m);
	assert(mok.get_variant()!!.count() == 6);
	Decoder mover = decoder(unhex("C6 07 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 07 00 00 00 01 00 00 00 07 00 00 00"), tmem, m);
	assert(@fails(mover.get_variant(), BAD_LENGTH));
}

fn void limits_exact_depth() @test
{
	Limits l = default_limits();
	l.max_depth = 4;
	DString ok = dstring::temp();
	for (int i = 0; i < 3; i++) ok.append("98 01 00 00 00 ");
	ok.append("00");
	Decoder fine = decoder(unhex(ok.str_view()), tmem, l);
	(void)fine.get_variant()!!;
	DString over = dstring::temp();
	for (int i = 0; i < 4; i++) over.append("98 01 00 00 00 ");
	over.append("00");
	Decoder bad = decoder(unhex(over.str_view()), tmem, l);
	assert(@fails(bad.get_variant(), DEPTH_EXCEEDED));
}

fn void limits_exact_message_size() @test
{
	Limits l = default_limits();
	l.max_message_size = 100;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	r.feed(mk_chunk('F', 1, 1, alloc::alloc_array(tmem, char, 100)))!!;
	assert(pull(&r).body.len == 100);
	r.feed(mk_chunk('F', 2, 2, alloc::alloc_array(tmem, char, 101)))!!;
	assert(next_fails(&r, MESSAGE_TOO_LARGE));
	ChunkReader m = new_reader(65536, l);                                                   // the total over several chunks counts
	defer m.free();
	m.feed(mk_chunk('C', 1, 1, alloc::alloc_array(tmem, char, 60)))!!;
	m.feed(mk_chunk('F', 2, 1, alloc::alloc_array(tmem, char, 40)))!!;
	assert(pull(&m).body.len == 100);
	ChunkReader n = new_reader(65536, l);
	defer n.free();
	n.feed(mk_chunk('C', 1, 1, alloc::alloc_array(tmem, char, 60)))!!;
	n.feed(mk_chunk('F', 2, 1, alloc::alloc_array(tmem, char, 41)))!!;
	assert(next_fails(&n, MESSAGE_TOO_LARGE), "one byte more in total");
}

fn void limits_exact_chunk_count() @test
{
	Limits l = default_limits();
	l.max_chunk_count = 3;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	r.feed(mk_chunk('C', 1, 1, unhex("01")))!!;
	r.feed(mk_chunk('C', 2, 1, unhex("02")))!!;
	r.feed(mk_chunk('F', 3, 1, unhex("03")))!!;
	assert(pull(&r).body == unhex("01 02 03"), "a message of exactly three chunks");
	ChunkReader o = new_reader(65536, l);
	defer o.free();
	o.feed(mk_chunk('C', 1, 1, unhex("01")))!!;
	o.feed(mk_chunk('C', 2, 1, unhex("02")))!!;
	o.feed(mk_chunk('C', 3, 1, unhex("03")))!!;
	o.feed(mk_chunk('F', 4, 1, unhex("04")))!!;
	assert(next_fails(&o, TOO_MANY_CHUNKS), "four chunks");
}

fn void limits_exact_pending_messages() @test
{
	Limits l = default_limits();
	l.max_pending_messages = 2;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	r.feed(mk_chunk('C', 1, 1, unhex("01")))!!;
	r.feed(mk_chunk('C', 2, 2, unhex("02")))!!;
	assert(nothing_more(&r) && nothing_more(&r) && r.partial_count == 2, "two partial messages");
	r.feed(mk_chunk('C', 3, 3, unhex("03")))!!;
	assert(next_fails(&r, TOO_MANY_PENDING), "the third");
}

fn void limits_exact_reassembly_bytes() @test
{
	Limits l = default_limits();
	l.max_reassembly_bytes = 100;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	r.feed(mk_chunk('C', 1, 1, alloc::alloc_array(tmem, char, 50)))!!;
	r.feed(mk_chunk('C', 2, 2, alloc::alloc_array(tmem, char, 50)))!!;
	assert(nothing_more(&r) && nothing_more(&r) && r.partial_bytes == 100, "exactly the limit");
	ChunkReader o = new_reader(65536, l);
	defer o.free();
	o.feed(mk_chunk('C', 1, 1, alloc::alloc_array(tmem, char, 50)))!!;
	o.feed(mk_chunk('C', 2, 2, alloc::alloc_array(tmem, char, 51)))!!;
	assert(next_fails(&o, MESSAGE_TOO_LARGE), "one byte more");
}

fn void limits_exact_outstanding_requests() @test
{
	Config c = session_config();
	c.limits.max_outstanding_requests = 3;
	Rig r;
	r.start(c);
	defer r.stop();
	for (int i = 0; i < 3; i++) (void)r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	assert(r.m.pending_count == 3);
	assert(@fails(r.m.send_read(&r.arena, at(1), one_node(), 0.0), TOO_MANY_PENDING));
}

fn void limits_exact_browse_pages_and_references() @test
{
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	// a page limit of 3 allows the first answer and three BrowseNext rounds: four pages in all
	for (uint pages = 1; pages <= 5; pages++)
	{
		ScriptTransport st;
		st.start();
		defer st.stop();
		st.total_pages = pages;
		Config cfg = client_config();
		cfg.limits.max_browse_pages = 3;
		Client* c = connect_script(&st, cfg);
		defer c.free();
		c.open_session()!!;
		if (pages <= 4)
		{
			assert(c.browse(&arena, nodeid_num(0, 85))!!.references.len == pages, "within the page limit");
		}
		else
		{
			assert(@fails(c.browse(&arena, nodeid_num(0, 85)), TOO_MANY_PAGES), "one round more than the limit");
			assert(st.release_seen == 1);
		}
	}
	// a reference limit of 3: three references are fine, four are not (one reference per page)
	for (uint pages = 1; pages <= 5; pages++)
	{
		ScriptTransport st;
		st.start();
		defer st.stop();
		st.total_pages = pages;
		Config cfg = client_config();
		cfg.limits.max_browse_references = 3;
		Client* c = connect_script(&st, cfg);
		defer c.free();
		c.open_session()!!;
		if (pages <= 3)
		{
			assert(c.browse(&arena, nodeid_num(0, 85))!!.references.len == pages);
		}
		else
		{
			assert(@fails(c.browse(&arena, nodeid_num(0, 85)), TOO_MANY_PAGES), "one reference more than the limit");
		}
	}
}

fn void limits_defaults_are_documented_values() @test
{
	Limits l = default_limits();
	assert(l.max_string_length == 1 << 20 && l.max_bytestring_length == 16 << 20 && l.max_array_length == 1_000_000);
	assert(l.max_matrix_elements == 1_000_000 && l.max_depth == 32 && l.max_message_size == 16 << 20 && l.max_chunk_count == 64);
	assert(l.max_pending_messages == 16 && l.max_reassembly_bytes == 16 << 20 && l.max_outstanding_requests == 64);
	assert(l.max_browse_pages == 1000 && l.max_browse_references == 1_000_000);
}
