module opcua;

// Hostile server replies end to end: random and mutated frames fed into the machine at every stage of a session. Every outcome
// is an event or a fault, the machine never crashes, and the memory it takes stays below max_message_size + 1 MiB (the machine
// and the decoded responses allocate from one arena whose high-water mark is checked).

const sz FUZZ_ARENA = 8 << 20;
const uint FUZZ_MESSAGE_LIMIT = 256 * 1024;

fn Config fuzz_config()
{
	Config c = session_config();
	c.limits.max_message_size = FUZZ_MESSAGE_LIMIT;
	c.limits.max_reassembly_bytes = FUZZ_MESSAGE_LIMIT;
	c.allow_write = true;
	return c;
}

fn char[] mutate_frame(Rng* rng, char[] frame)
{
	char[] data = cat(frame, {});
	switch (rng.next() % 6u)
	{
		case 0:
			int flips = 1 + (int)(rng.next() % 3u);
			for (int i = 0; i < flips; i++) data[(sz)(rng.next() % (ulong)data.len)] ^= (char)(1 << (rng.next() % 8u));
		case 1: return data[:(sz)(rng.next() % (ulong)data.len)];
		case 2:
			sz extra = 1 + (sz)(rng.next() % 16u);
			char[] longer = alloc::alloc_array(tmem, char, data.len + extra);
			mem::copy(longer.ptr, data.ptr, data.len);
			for (sz i = 0; i < extra; i++) longer[data.len + i] = (char)rng.next();
			return longer;
		case 3:
			char[] noise = alloc::alloc_array(tmem, char, 1 + (sz)(rng.next() % 600u));
			foreach (&b : noise) *b = (char)rng.next();
			return noise;
		case 4:
			for (sz i = 0; i < 24 && i < data.len; i++)
			{
				if (rng.next() % 4u == 0) data[i] = (char)rng.next();
			}
		default:
			if (data.len >= 8)
			{
				uint size = (uint)rng.next();
				data[4] = (char)size;
				data[5] = (char)(size >> 8);
				data[6] = (char)(size >> 16);
				data[7] = (char)(size >> 24);
			}
	}
	return data;
}

fn void drain_events(Machine* m)
{
	Event e;
	while (m.poll_event(&e))
	{
		assert((int)e.kind >= 0 && (int)e.kind <= 6);
	}
}

// One step of the recorded session; `data` replaces the recorded server frame.
fn void fuzz_step(Machine* m, Allocator alloc, int step, char[] data, Now now)
{
	switch (step)
	{
		case 0: (void)m.feed(data, now);
		case 1: (void)m.feed(data, now);
		case 2:
			(void)m.open_session(identity_anonymous(), now);
			(void)m.feed(data, now);
		case 3: (void)m.feed(data, now);
		case 4:
			ReadValueId[1] node = { { .node_id = nodeid_num(0, 2259), .attribute_id = 13 } };
			(void)m.send_read(alloc, now, &node, 0.0);
			(void)m.feed(data, now);
		default:
			(void)m.close(now);
			(void)m.feed(data, now);
	}
	eat(m);
	drain_events(m);
	assert(m.pending_count <= m.config.limits.max_outstanding_requests);
}

fn void fuzz_machine_ten_thousand_iterations() @test
{
	String[6] frames = { REAL_SESSION_ACK, REAL_SESSION_OPN, REAL_SESSION_CREATE, REAL_SESSION_ACTIVATE, REAL_SESSION_READ, REAL_SESSION_CLOSE };
	char[] store = alloc::alloc_array(mem, char, FUZZ_ARENA);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	Rng rng = { 0x9E3779B97F4A7C15 };
	sz high_water = 0;
	int faults = 0;
	for (int it = 0; it < 10000; it++)
	{
		arena.init(store);
		Machine m;
		m.init(&arena, fuzz_config());
		(void)m.connect("opc.tcp://127.0.0.1:4850", at(0));
		eat(&m);
		int hit = (int)(rng.next() % 6u);
		int second = rng.next() % 3u == 0 ? (int)(rng.next() % 6u) : -1;                 // sometimes two stages are hostile
		for (int step = 0; step < 6; step++)
		{
			char[] data = unhex(frames[step]);
			if (step == hit || step == second) data = mutate_frame(&rng, data);
			fuzz_step(&m, &arena, step, data, at((ulong)step + 1));
			if (m.state == State.FAILED) faults++;
		}
		assert((int)m.state >= 0 && (int)m.state <= (int)State.FAILED);
		if (arena.used > high_water) high_water = arena.used;
		m.free();
	}
	assert(high_water < (sz)FUZZ_MESSAGE_LIMIT + (1 << 20), "the memory stays below max_message_size plus 1 MiB");
	assert(faults > 100, "the fuzzer does reach the failure paths");
}

// Purely random bytes against a fresh machine at every stage.
fn void fuzz_machine_random_streams() @test
{
	char[] store = alloc::alloc_array(mem, char, FUZZ_ARENA);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	Rng rng = { 0xD1B54A32D192ED03 };
	for (int it = 0; it < 2000; it++)
	{
		arena.init(store);
		Machine m;
		m.init(&arena, fuzz_config());
		(void)m.connect("opc.tcp://127.0.0.1:4850", at(0));
		eat(&m);
		for (int k = 0; k < 4; k++)
		{
			char[] noise = alloc::alloc_array(tmem, char, 1 + (sz)(rng.next() % 300u));
			foreach (&b : noise) *b = (char)rng.next();
			if (rng.next() % 2u == 0 && noise.len >= 8)
			{
				noise[0] = 'M';                                                         // plausible frame headers get further
				noise[1] = 'S';
				noise[2] = 'G';
				noise[3] = 'F';
				noise[4] = (char)noise.len;
				noise[5] = 0;
				noise[6] = 0;
				noise[7] = 0;
			}
			(void)m.feed(noise, at((ulong)k));
			drain_events(&m);
		}
		assert(arena.used < (sz)FUZZ_MESSAGE_LIMIT + (1 << 20));
		m.free();
	}
}

// D4: every single bit of B4, B7 and B8 flipped, fed to a machine in the state where the frame is meaningful.
fn void bitflip_b_frames_end_to_end() @test
{
	char[] store = alloc::alloc_array(mem, char, FUZZ_ARENA);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	sz high_water = 0;
	char[][3] frames = { cat(unhex(B4_HEAD), unhex(B4_BODY)), b7_frame(), unhex(B8_RESPONSE) };
	for (int which = 0; which < 3; which++)
	{
		char[] frame = frames[which];
		for (sz byte = 0; byte < frame.len; byte++)
		{
			for (int bit = 0; bit < 8; bit++)
			{
				arena.init(store);
				Machine m;
				Config c = fuzz_config();
				m.init(&arena, c);
				FakeServer s = fake_server();
				char[] bad = cat(frame, {});
				bad[byte] ^= (char)(1 << bit);
				if (which == 0)
				{
					(void)m.connect(URL, at(0));
					eat(&m);
					(void)m.feed(s.ack(), at(1));
					eat(&m);
					(void)m.feed(bad, at(2));
				}
				else
				{
					open_active(&m, &s);
					if (which == 2)
					{
						m.token_id = 2;
						m.next_request_id = 4;
						m.next_handle = 4;
						m.reader.last_sequence = 5;
						(void)m.send_read(&arena, at(3), one_node(), 0.0);
					}
					eat(&m);
					(void)m.feed(bad, at(4));
				}
				eat(&m);
				drain_events(&m);
				if (arena.used > high_water) high_water = arena.used;
				m.free();
			}
		}
	}
	assert(high_water < (sz)FUZZ_MESSAGE_LIMIT + (1 << 20));
}
