module opcua;

// Robustness of the channel machine: duplicate answers, foreign chunks, bad configuration, memory exhaustion.

// A server that is only slow answers both the first renewal and its retry: neither answer may hurt the channel.
fn void robust_duplicate_renew_answer() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 10000;
	open_channel(&m, &s, 0, 60000);
	m.handle_timeout(at(45000))!!;
	eat(&m);
	uint first = m.renew_ids[0];
	m.handle_timeout(at(55000))!!;
	(void)next_kind(&m);
	eat(&m);
	uint second = m.renew_ids[1];
	m.feed(s.opn_response(first, m.open_handle, 7, 2, 60000), at(55500))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEWED);
	m.feed(s.opn_response(second, m.open_handle, 7, 3, 60000), at(55600))!!;
	assert(m.state == State.CHANNEL_OPEN && no_events(&m), "the second answer is dropped quietly");
	assert(m.token_id == 2, "the first answer stays the current token");
	// an OPN answer nobody asked for is still a violation
	assert(@fails(m.feed(s.opn_response(999, m.open_handle, 7, 4, 60000), at(55700)), BAD_RESPONSE));
}

fn void robust_abort_needs_the_right_channel_and_token() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	(void)m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[] foreign = mk_abort(s.seq, 2, 0x80010000, "x");
	foreign[8] = 99;                                                                        // another channel
	assert(@fails(m.feed(foreign, at(2)), CHANNEL_ID_MISMATCH));
	assert(m.pending_count == 0 || m.state == State.FAILED);
	Machine t;
	t.init(mem, test_config());
	defer t.free();
	FakeServer u = fake_server();
	open_channel(&t, &u);
	(void)t.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[] other_token = mk_abort(u.seq, 2, 0x80010000, "x");
	other_token[12] = 55;                                                                   // unknown token
	assert(@fails(t.feed(other_token, at(2)), TOKEN_UNKNOWN));
	Event e;
	while (t.poll_event(&e))
	{
		if (e.kind == EventKind.RESPONSE) assert((uint)e.response.header.service_result == 0x80AE0000, "only the failure answer");
	}
}

fn void robust_zero_config_values() @test
{
	for (int i = 0; i < 3; i++)
	{
		Config c = test_config();
		switch (i)
		{
			case 0: c.request_timeout_ms = 0;
			case 1: c.handshake_timeout_ms = 0;
			default: c.channel_lifetime_ms = 0;
		}
		Machine m;
		m.init(mem, c);
		defer m.free();
		assert(@fails(m.connect(URL, at(0)), BAD_LENGTH));
		assert(m.state == State.IDLE && m.pending_output().len == 0);
	}
}

// Events are never lost silently: when memory runs out the machine fails and says so.
fn void robust_lost_events_become_failed() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	for (int i = 0; i < 9; i++) (void)m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[256] store;
	ArenaAllocator none;
	none.init(store[:0]);
	Allocator real = m.allocator;
	m.allocator = &none;                                                                     // no memory for more events
	m.transport_closed(at(2));
	m.allocator = real;
	assert(m.state == State.FAILED);
	int responses = 0;
	EventKind last = EventKind.CHANNEL_OPEN;
	Event e;
	while (m.poll_event(&e))
	{
		if (e.kind == EventKind.RESPONSE) responses++;
		last = e.kind;
	}
	assert(responses == 8 && last == EventKind.FAILED, "the event queue ends in FAILED");
	assert(no_events(&m));
}

fn void robust_failed_connect_leaves_no_state() @test
{
	char[64] store;
	ArenaAllocator small;
	small.init(&store);
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	Allocator real = m.allocator;
	m.allocator = &small;                                                                    // room for the URL copy, not for the HEL
	m.outbox.allocator = &small;
	assert(!@ok(m.connect(URL, at(0))), "the HEL does not fit");
	m.allocator = real;
	m.outbox.allocator = real;
	assert(m.state == State.IDLE && m.endpoint_url.ptr == null && m.pending_output().len == 0);
	m.connect(URL, at(0))!!;
	assert(m.state == State.HEL_SENT && m.pending_output() == unhex(B1_HEL));
}

fn void robust_short_error_body() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	eat(&m);
	assert(@fails(m.feed(unhex("45 52 52 46 0A 00 00 00 01 02"), at(0)), PEER_ERROR));
	assert(m.state == State.FAILED && m.failure == PEER_ERROR);
}

// A lost event must not leave requests behind: every pending request still gets its answer before FAILED, and a failed
// machine schedules nothing.
fn void robust_lost_event_completes_the_rest() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	for (int i = 0; i < 9; i++) (void)m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	(void)m.send_raw(tmem, at(5000), nodeid_num(0, 631), {})!!;
	char[256] store;
	ArenaAllocator none;
	none.init(store[:0]);
	Allocator real = m.allocator;
	m.allocator = &none;
	m.handle_timeout(at(1500))!!;                                                           // nine requests expire, the ninth event is lost
	m.allocator = real;
	int responses = 0;
	EventKind last = EventKind.CHANNEL_OPEN;
	Event e;
	while (m.poll_event(&e))
	{
		if (e.kind == EventKind.RESPONSE) responses++;
		last = e.kind;
	}
	assert(last == EventKind.FAILED && m.state == State.FAILED && m.failure == BUFFER_FULL);
	assert(m.pending_count == 0, "no request is left without an answer");
	assert(responses == 9, "eight queued answers and the request that was still pending");
	ulong d;
	assert(!m.next_deadline(&d), "a failed machine schedules nothing");
}

fn void robust_terminal_states_have_no_deadline() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	ulong d;
	assert(!m.next_deadline(&d));
	open_channel(&m, &s);
	(void)m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	assert(m.next_deadline(&d));
	m.transport_closed(at(2));
	assert(m.state == State.FAILED && !m.next_deadline(&d));
	Machine c;
	c.init(mem, test_config());
	defer c.free();
	FakeServer t = fake_server();
	open_channel(&c, &t);
	c.close(at(1))!!;
	eat(&c);
	assert(c.state == State.CLOSED && !c.next_deadline(&d));
}

// The channel renewal is not a session request: its header carries no AuthenticationToken even when a session exists.
fn void robust_renewal_header_has_no_session_token() @test
{
	Machine m;
	Config c = session_config();
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s, "", identity_anonymous(), 0);
	eat(&m);
	m.handle_timeout(at(m.next_renew_ms))!!;
	Message r = first_message(m.pending_output());
	assert(r.type == MsgType.OPN);
	assert(r.body[:4] == unhex("01 00 BE 01") && r.body[4:2] == unhex("00 00"), "a null AuthenticationToken");
	assert(load_u32_test(r.body, 37) == 1, "RequestType Renew");
}
