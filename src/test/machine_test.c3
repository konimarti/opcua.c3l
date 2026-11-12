module opcua;

// Handshake and SecureChannel None: HEL/ACK, OPN issue and renew with retry, CLO, failure handling, the request table.
// Vectors B1, B4, B5, B6, M10, M11, M19, M20, M26, M29, M94, M96, D6, D7 and the extras named in the comments.

const String URL = "opc.tcp://localhost:4840";

fn Config test_config()
{
	Config c = default_config();
	c.request_timeout_ms = 1000;       // the TimeoutHint of the OPN request vector
	return c;
}

fn Now at(ulong ms) => { .mono_ms = ms };

fn void eat(Machine* m)
{
	m.consume_output(m.pending_output().len);
}

fn EventKind next_kind(Machine* m)
{
	Event e;
	assert(m.poll_event(&e), "an event is expected");
	return e.kind;
}

fn bool no_events(Machine* m)
{
	Event e;
	return !m.poll_event(&e);
}

// Connects, answers HEL and OPN from the scripted server: channel 7, token 1, the given lifetime.
fn void open_channel(Machine* m, FakeServer* s, ulong t = 0, uint lifetime = 3600000)
{
	m.connect(URL, at(t))!!;
	eat(m);
	m.feed(s.ack(), at(t))!!;
	eat(m);
	m.feed(s.opn_response(1, 1, 7, 1, lifetime), at(t))!!;
	assert(m.state == State.CHANNEL_OPEN);
	assert(next_kind(m) == EventKind.CHANNEL_OPEN);
}

// The bytes of every frame in `out`, parsed with an independent reader.
fn Message first_message(char[] out)
{
	ChunkReader r;
	r.init(tmem, default_limits(), 65536);       // released with the temp allocator, so the message stays valid
	r.feed(out)!!;
	Message m = pull(&r);
	return m;
}

// ---------- handshake_bytes ----------
fn void handshake_bytes() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	assert(m.state == State.HEL_SENT);
	assert(m.pending_output() == unhex(B1_HEL));                                          // B1
	eat(&m);
	assert(m.pending_output().len == 0);
	m.feed(s.ack(), at(5))!!;
	assert(m.state == State.OPN_SENT);
	assert(m.pending_output() == cat(unhex(B4_HEAD), unhex(B4_BODY)));                    // B4
	assert(m.writer.next_sequence == 2);
}

fn void handshake_connect_rules() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	assert(@fails(m.feed(unhex("00"), at(0)), BAD_STATE));
	DString url = dstring::temp();
	for (int i = 0; i < 5000; i++) url.append("a");
	assert(@fails(m.connect(url.str_view(), at(0)), URL_INVALID));
	assert(m.state == State.IDLE && m.pending_output().len == 0);
	m.connect(URL, at(0))!!;
	assert(@fails(m.connect(URL, at(0)), BAD_STATE));
	// security other than None is refused before anything is queued
	Config c = test_config();
	c.security_mode = MessageSecurityMode.SIGN;
	Machine sec;
	sec.init(mem, c);
	defer sec.free();
	assert(@fails(sec.connect(URL, at(0)), SECURITY_UNSUPPORTED));
	assert(sec.state == State.IDLE && sec.pending_output().len == 0);
	Config p = test_config();
	p.security_policy_uri = POLICY_BASIC256SHA256;
	Machine pol;
	pol.init(mem, p);
	defer pol.free();
	assert(@fails(pol.connect(URL, at(0)), SECURITY_UNSUPPORTED));
	Machine sess;
	sess.init(mem, test_config());
	defer sess.free();
	assert(@fails(sess.open_session(identity_anonymous(), at(0)), BAD_STATE));
}

// ---------- ack_rules ----------
fn void ack_rules_buffers_and_limits() @test
{
	Config c = test_config();
	c.send_buffer_size = 32768;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	eat(&m);
	m.feed(s.ack(16384, 65536, 1000000, 50), at(0))!!;
	assert(m.writer.max_chunk_size == 16384, "the smaller of our send buffer and the peer's receive buffer");
	assert(m.writer.max_message_size == 1000000 && m.writer.max_chunk_count == 50);
	assert(m.reader.max_chunk_size == 65536, "we enforce our own receive buffer");
	Machine n;
	n.init(mem, c);
	defer n.free();
	n.connect(URL, at(0))!!;
	eat(&n);
	n.feed(s.ack(1 << 20, 65536), at(0))!!;
	assert(n.writer.max_chunk_size == 32768);
	assert(n.writer.max_message_size == 0 && n.writer.max_chunk_count == 0, "0 means unlimited");
	Machine exact;
	exact.init(mem, c);
	defer exact.free();
	exact.connect(URL, at(0))!!;
	eat(&exact);
	exact.feed(s.ack(8192, 8192), at(0))!!;
	assert(exact.state == State.OPN_SENT && exact.writer.max_chunk_size == 8192);
}

fn void ack_rules_violations() @test
{
	FakeServer s = fake_server();
	char[][] bad = { s.ack(100, 65536), s.ack(65536, 100), s.ack(8191, 65536), s.ack(65536, 65536, 0, 0, 99), s.ack(65536, 65536, 0, 0, 1) };
	foreach (frame : bad)                                                                 // M10, M11
	{
		Machine m;
		m.init(mem, test_config());
		defer m.free();
		m.connect(URL, at(0))!!;
		eat(&m);
		assert(@fails(m.feed(frame, at(0)), BAD_HANDSHAKE));
		assert(m.state == State.FAILED && m.failure == BAD_HANDSHAKE);
		assert(next_kind(&m) == EventKind.FAILED);
		assert(m.pending_output().len == 0, "no OPN after a refused ACK");
	}
	Machine other;                                                                         // an OPN before the ACK
	other.init(mem, test_config());
	defer other.free();
	other.connect(URL, at(0))!!;
	assert(@fails(other.feed(s.opn_response(1, 1, 7, 1, 1000), at(0)), BAD_HANDSHAKE));
}

// ---------- open_response ----------
fn void open_response_installs_the_token() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(100))!!;
	eat(&m);
	m.feed(s.ack(), at(100))!!;
	eat(&m);
	m.feed(s.opn_response(1, 1, 7, 3, 60000), at(250))!!;                                 // first sequence number 77 is accepted
	assert(m.state == State.CHANNEL_OPEN && m.channel_id == 7 && m.token_id == 3);
	assert(m.lifetime_ms == 60000 && m.token_issued_ms == 250, "the local clock, not CreatedAt");
	assert(next_kind(&m) == EventKind.CHANNEL_OPEN && no_events(&m));
	ulong d;
	assert(m.next_deadline(&d) && d == 250 + 45000);
}

fn void open_response_lifetime_rules() @test
{
	Machine zero;                                                                          // RevisedLifetime 0 is replaced by a local default
	zero.init(mem, test_config());
	defer zero.free();
	FakeServer s = fake_server();
	open_channel(&zero, &s, 0, 0);
	assert(zero.lifetime_ms == 600000);
	ulong d;
	assert(zero.next_deadline(&d) && d == 450000);
	Machine tiny;                                                                          // M96: 1 ms is not a busy loop
	tiny.init(mem, test_config());
	defer tiny.free();
	FakeServer t = fake_server();
	open_channel(&tiny, &t, 5000, 1);
	assert(tiny.lifetime_ms >= 2000 && tiny.next_deadline(&d) && d >= 5000 + 1000, "a renewal is never scheduled sooner than 1000 ms");
	tiny.handle_timeout(at(d))!!;
	assert(tiny.state == State.CHANNEL_OPEN && tiny.renew_pending);
	assert(tiny.next_deadline(&d) && d >= 6000);
}

fn void open_response_errors() @test
{
	// M19: another policy URI; M20: channel id 0
	FakeServer s = fake_server();
	char[][] frames = { s.opn_response(1, 1, 7, 1, 1000, OTHER_URI_FULL), s.opn_response(1, 1, 0, 1, 1000) };
	fault[] want = { BAD_HANDSHAKE, BAD_HANDSHAKE };
	foreach (i, frame : frames)
	{
		Machine m;
		m.init(mem, test_config());
		defer m.free();
		m.connect(URL, at(0))!!;
		eat(&m);
		m.feed(s.ack(), at(0))!!;
		eat(&m);
		assert(@fails(m.feed(frame, at(0)), want[i]));
		assert(m.state == State.FAILED);
	}
	// wrong request id / handle, a bad service result, a service fault, trailing bytes
	char[][] others = { s.opn_response(9, 1, 7, 1, 1000), s.opn_response(1, 9, 7, 1, 1000), s.opn_response(1, 1, 7, 1, 1000, NONE_URI_FULL, 0x80010000) };
	fault[] wanted = { BAD_RESPONSE, BAD_RESPONSE, SERVICE_FAULT };
	foreach (i, frame : others)
	{
		Machine m;
		m.init(mem, test_config());
		defer m.free();
		m.connect(URL, at(0))!!;
		eat(&m);
		m.feed(s.ack(), at(0))!!;
		eat(&m);
		assert(@fails(m.feed(frame, at(0)), wanted[i]));
	}
	Machine r;                                                                             // the channel id in the asymmetric header must match the token
	r.init(mem, test_config());
	defer r.free();
	r.connect(URL, at(0))!!;
	eat(&r);
	r.feed(s.ack(), at(0))!!;
	eat(&r);
	char[] frame = s.opn_response(1, 1, 7, 1, 1000);
	frame[8] = 8;                                                                          // SecureChannelId of the frame header
	assert(@fails(r.feed(frame, at(0)), CHANNEL_ID_MISMATCH));
}

// ---------- renew_timer (D7) ----------
fn void renew_timer() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s, 0, 60000);
	ulong d;
	assert(m.next_deadline(&d) && d == 45000, "75% of 60000 ms");
	m.handle_timeout(at(44999))!!;
	assert(m.pending_output().len == 0 && !m.renew_pending, "none earlier");
	m.handle_timeout(at(45000))!!;
	assert(m.renew_pending);
	Message r = first_message(m.pending_output());
	assert(r.type == MsgType.OPN && r.channel_id == 7 && r.policy_uri == POLICY_NONE);
	assert(load_u32_test(r.body, 37) == 1, "RequestType Renew");
	assert(load_u32_test(r.body, 49) == 3600000, "the requested lifetime");
	assert(no_events(&m));
}

fn void renew_retry_answered_on_the_second_try() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 10000;
	open_channel(&m, &s, 0, 60000);
	m.handle_timeout(at(45000))!!;
	eat(&m);
	ulong d;
	assert(m.next_deadline(&d) && d == 55000, "retry after request_timeout_ms");
	m.handle_timeout(at(55000))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEW_FAILED && no_events(&m));
	assert(m.state == State.CHANNEL_OPEN, "the channel is still open");
	assert(m.pending_output().len > 0, "a new renewal request was queued");
	eat(&m);
	assert(m.next_deadline(&d) && d == 60000, "the old token's end comes before the next retry");
	uint second = m.renew_ids[1];
	m.feed(s.opn_response(second, m.open_handle, 7, 2, 60000), at(56000))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEWED);
	assert(m.state == State.CHANNEL_OPEN && m.token_id == 2 && !m.renew_pending && m.token_issued_ms == 56000);
	assert(m.next_deadline(&d) && d == 56000 + 45000);
}

fn void renew_retry_answer_to_the_first_try_counts() @test
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
	m.feed(s.opn_response(first, 1, 7, 2, 60000), at(55500))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEWED);
}

fn void renew_never_answered_fails_at_the_lifetime_end() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 10000;
	open_channel(&m, &s, 0, 60000);
	m.handle_timeout(at(45000))!!;
	m.handle_timeout(at(55000))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEW_FAILED);
	ulong d;
	assert(m.next_deadline(&d) && d == 60000);
	m.handle_timeout(at(59999))!!;
	assert(m.state == State.CHANNEL_OPEN);
	assert(@fails(m.handle_timeout(at(60000)), TIMEOUT));
	assert(m.state == State.FAILED && m.failure == TIMEOUT);
	assert(next_kind(&m) == EventKind.FAILED);
}

// The sequence counter is per direction and continues across a renewal.
fn void renew_sequence_continues() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s, 0, 60000);
	m.handle_timeout(at(45000))!!;
	char[] renew = cat(m.pending_output(), {});
	eat(&m);
	assert(load_u32_test(renew, 71) == 2, "the Issue request used 1, the Renew request uses 2");
	m.feed(s.opn_response(m.renew_ids[0], m.open_handle, 7, 2, 60000), at(45100))!!;
	(void)next_kind(&m);
	m.send_raw(tmem, at(45200), nodeid_num(0, 631), {})!!;
	char[] msg = cat(m.pending_output(), {});
	assert(load_u32_test(msg, 16) == 3 && load_u32_test(msg, 12) == 2, "sequence 3 under the new token");
}

// While a renewal is pending, requests go out under the old, still valid token.
fn void renew_pending_requests_use_the_old_token() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 100000;
	open_channel(&m, &s, 0, 60000);
	m.handle_timeout(at(45000))!!;
	assert(m.renew_pending);
	eat(&m);
	m.send_raw(tmem, at(45100), nodeid_num(0, 631), {})!!;
	char[] chunk = cat(m.pending_output(), {});
	assert(load_u32_test(chunk, 12) == 1, "the old token");
	eat(&m);
	m.feed(s.opn_response(m.renew_ids[0], m.open_handle, 7, 2, 60000), at(45200))!!;
	m.send_raw(tmem, at(45300), nodeid_num(0, 631), {})!!;
	assert(load_u32_test(m.pending_output(), 12) == 2, "the new token once it is installed");
}

// D6: the sequence number wrap, in both directions of the machine.
fn void sequence_wrap_in_the_machine() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server(7, 0xFFFFFBFF);                                             // the OPN response already carries a high value
	open_channel(&m, &s);
	uint h = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	s.seq = 1;                                                                             // 0xFFFFFBFF followed by 1 is a legal wrap
	m.feed(s.msg(2, h, 1), at(2))!!;
	Event e;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE && e.response.handle == h);
	Machine c;                                                                             // our own counter wraps the same way
	c.init(mem, test_config());
	defer c.free();
	FakeServer t = fake_server();
	open_channel(&c, &t);
	eat(&c);
	c.writer.next_sequence = 0xFFFFFC00;
	c.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[] first = cat(c.pending_output(), {});
	eat(&c);
	c.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[] second = cat(c.pending_output(), {});
	assert(load_u32_test(first, 16) == 0xFFFFFC00 && load_u32_test(second, 16) == 1);
	Machine g;                                                                             // a gap after the wrap is still an error
	g.init(mem, test_config());
	defer g.free();
	FakeServer u = fake_server(7, 0xFFFFFBFF);
	open_channel(&g, &u);
	uint gh = g.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	u.seq = 0x400;                                                                         // 1024 is not below 1024
	assert(@fails(g.feed(u.msg(2, gh, 1), at(2)), SEQUENCE_ERROR));
}

// ---------- old_token_window (M94, S3) ----------
fn void old_token_window() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 100000;
	open_channel(&m, &s, 0, 60000);
	uint h1 = m.send_raw(tmem, at(100), nodeid_num(0, 631), {})!!;
	uint h2 = m.send_raw(tmem, at(100), nodeid_num(0, 631), {})!!;
	uint h3 = m.send_raw(tmem, at(100), nodeid_num(0, 631), {})!!;
	eat(&m);
	m.handle_timeout(at(45000))!!;
	eat(&m);
	m.feed(s.opn_response(m.renew_ids[0], m.open_handle, 7, 2, 60000), at(45100))!!;
	assert(next_kind(&m) == EventKind.CHANNEL_RENEWED);
	m.feed(s.msg(2, h1, 1), at(45200))!!;                                                  // a reply under the old token is accepted
	Event e;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE && e.response.handle == h1);
	m.feed(s.msg(3, h2, 2), at(45300))!!;                                                  // the first chunk under the new token ends the old window
	assert(m.poll_event(&e) && e.response.handle == h2);
	assert(@fails(m.feed(s.msg(4, h3, 1), at(45400)), TOKEN_UNKNOWN));
}

fn void old_token_expires() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.config.request_timeout_ms = 100000;
	open_channel(&m, &s, 0, 60000);
	uint h1 = m.send_raw(tmem, at(100), nodeid_num(0, 631), {})!!;
	eat(&m);
	m.handle_timeout(at(45000))!!;
	eat(&m);
	m.feed(s.opn_response(m.renew_ids[0], m.open_handle, 7, 2, 60000), at(45100))!!;
	(void)next_kind(&m);
	assert(@fails(m.feed(s.msg(2, h1, 1), at(60000)), TOKEN_UNKNOWN), "the old token's lifetime has ended");
}

// ---------- close_bytes (B6), double_close ----------
fn void close_bytes() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.channel_id = 7;
	m.token_id = 2;
	m.writer.next_sequence = 5;
	m.next_request_id = 3;
	m.next_handle = 3;
	m.close(at(10))!!;
	assert(m.state == State.CLOSING);
	assert(m.pending_output() == unhex(B6_CLO));                                          // B6
	assert(no_events(&m), "CLOSED comes after the transport took the bytes");
	m.consume_output(10);
	assert(m.state == State.CLOSING);
	eat(&m);
	assert(m.state == State.CLOSED && next_kind(&m) == EventKind.CLOSED && no_events(&m));
}

fn void double_close() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.close(at(1))!!;
	m.close(at(2))!!;
	assert(m.state == State.CLOSING);
	sz once = m.pending_output().len;
	eat(&m);
	assert(once == 24 + 4 + 29, "one CLO chunk: headers, type id, request header");
	m.close(at(3))!!;
	assert(m.pending_output().len == 0 && m.state == State.CLOSED);
	assert(next_kind(&m) == EventKind.CLOSED && no_events(&m), "one CLOSED event");
	assert(@fails(m.send_raw(tmem, at(4), nodeid_num(0, 631), {}), BAD_STATE));
	assert(@fails(m.feed(unhex("00"), at(5)), BAD_STATE));
	m.transport_closed(at(6));
	assert(m.state == State.CLOSED && no_events(&m));
	Machine idle;
	idle.init(mem, test_config());
	defer idle.free();
	idle.close(at(0))!!;
	idle.close(at(0))!!;
	assert(idle.state == State.CLOSED);
	Machine early;                                                                         // close during the handshake
	early.init(mem, test_config());
	defer early.free();
	early.connect(URL, at(0))!!;
	early.close(at(1))!!;
	assert(early.state == State.CLOSED && next_kind(&early) == EventKind.CLOSED);
}

// ---------- failure_completes_pending ----------
fn void failure_completes_pending() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	uint h1 = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	uint h2 = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	eat(&m);
	assert(@fails(m.feed(unhex(B3_ERR), at(2)), PEER_ERROR));                             // B3 (the same frame the plan calls an ERR)
	assert((uint)m.last_status == 0x80800000 && m.state == State.FAILED && m.failure == PEER_ERROR);
	Event e;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE && e.response.kind == ResponseKind.SERVICE_FAULT);
	assert((uint)e.response.header.service_result == 0x80AE0000 && !e.response.local_timeout);
	uint first = e.response.handle;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE && (uint)e.response.header.service_result == 0x80AE0000);
	assert((first == h1 && e.response.handle == h2) || (first == h2 && e.response.handle == h1));
	assert(m.poll_event(&e) && e.kind == EventKind.FAILED && no_events(&m), "FAILED comes after every response");
	assert(@fails(m.send_raw(tmem, at(3), nodeid_num(0, 631), {}), BAD_STATE));
	assert(@fails(m.feed(unhex("00"), at(3)), BAD_STATE));
}

fn void failure_transport_closed() @test
{
	Machine mid;
	mid.init(mem, test_config());
	defer mid.free();
	FakeServer s = fake_server();
	open_channel(&mid, &s);
	char[] frame = s.msg(2, 1, 1);
	mid.feed(frame[:10], at(1))!!;
	mid.transport_closed(at(2));
	assert(mid.state == State.FAILED && mid.failure == TRANSPORT_TRUNCATED);
	Machine between;
	between.init(mem, test_config());
	defer between.free();
	FakeServer t = fake_server();
	open_channel(&between, &t);
	between.transport_closed(at(2));
	assert(between.state == State.FAILED && between.failure == CLOSED);
	Machine early;                                                                         // before the first ACK
	early.init(mem, test_config());
	defer early.free();
	early.connect(URL, at(0))!!;
	early.transport_closed(at(1));
	assert(early.failure == CLOSED && early.state == State.FAILED);
	Machine closing;                                                                       // the peer hangs up after our CLO
	closing.init(mem, test_config());
	defer closing.free();
	FakeServer u = fake_server();
	open_channel(&closing, &u);
	closing.close(at(1))!!;
	closing.transport_closed(at(2));
	assert(closing.state == State.CLOSED);
}

// ---------- errors ----------
fn void errors_peer_error_during_the_handshake() @test
{
	Machine m;                                                                              // M29
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	eat(&m);
	m.feed(s.ack(), at(0))!!;
	eat(&m);
	assert(@fails(m.feed(s.error(0x80010000), at(0)), PEER_ERROR));
	assert((uint)m.last_status == 0x80010000 && m.state == State.FAILED);
	Machine h;                                                                              // an ERR instead of the ACK
	h.init(mem, test_config());
	defer h.free();
	h.connect(URL, at(0))!!;
	assert(@fails(h.feed(s.error(), at(0)), PEER_ERROR));
	assert((uint)h.last_status == 0x80800000);
}

fn void errors_channel() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	uint h = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	assert(@fails(m.feed(s.msg(2, h, 99), at(2)), TOKEN_UNKNOWN));                         // M26
	Machine c;
	c.init(mem, test_config());
	defer c.free();
	FakeServer t = fake_server();
	open_channel(&c, &t);
	uint ch = c.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	t.channel = 8;
	assert(@fails(c.feed(t.msg(2, ch, 1), at(2)), CHANNEL_ID_MISMATCH));
	Machine q;
	q.init(mem, test_config());
	defer q.free();
	FakeServer u = fake_server();
	open_channel(&q, &u);
	uint qh = q.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	(void)u.msg(2, qh, 1);                                                                  // a lost chunk
	assert(@fails(q.feed(u.msg(2, qh, 1), at(2)), SEQUENCE_ERROR));
	Machine o;                                                                              // an OPN answer nobody asked for
	o.init(mem, test_config());
	defer o.free();
	FakeServer v = fake_server();
	open_channel(&o, &v);
	assert(@fails(o.feed(v.opn_response(5, 1, 7, 2, 1000), at(2)), BAD_RESPONSE));
	Machine z;                                                                              // a CLO from the server
	z.init(mem, test_config());
	defer z.free();
	FakeServer w = fake_server();
	open_channel(&z, &w);
	char[] clo = w.msg(2, 1, 1);
	clo[0] = 'C';
	clo[1] = 'L';
	clo[2] = 'O';
	assert(@fails(z.feed(clo, at(2)), CHANNEL_CLOSED));
}

fn void errors_service_responses() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	uint h = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	assert(@fails(m.feed(s.msg(2, h + 5, 1), at(2)), BAD_RESPONSE), "handle mismatch");
	Machine f;
	f.init(mem, test_config());
	defer f.free();
	FakeServer t = fake_server();
	open_channel(&f, &t);
	uint fh = f.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	f.feed(t.service_fault(2, fh, 1, 0x80740000), at(2))!!;
	Event e;
	assert(f.poll_event(&e) && e.kind == EventKind.RESPONSE && e.response.kind == ResponseKind.SERVICE_FAULT && e.response.handle == fh);
	assert((uint)e.response.header.service_result == 0x80740000 && !e.response.local_timeout && (uint)f.last_status == 0x80740000);
	assert(f.state == State.CHANNEL_OPEN, "a ServiceFault is an answer, not a failure");
	Machine r;
	r.init(mem, test_config());
	defer r.free();
	FakeServer u = fake_server();
	open_channel(&r, &u);
	uint rh = r.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	r.feed(u.msg(2, rh, 1, ID_READ_RESPONSE, "AA BB CC"), at(2))!!;
	assert(r.poll_event(&e) && e.response.kind == ResponseKind.RAW && e.response.raw == unhex("AA BB CC"));
	Machine ab;                                                                             // an abort chunk completes exactly that request
	ab.init(mem, test_config());
	defer ab.free();
	FakeServer v = fake_server();
	open_channel(&ab, &v);
	uint a1 = ab.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	uint a2 = ab.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	char[] abort = mk_abort(v.seq, 2, 0x80010000, "x");
	abort[8] = 7;
	ab.feed(abort, at(2))!!;
	assert(ab.poll_event(&e) && e.response.handle == a1 && (uint)e.response.header.service_result == 0x80010000);
	assert(no_events(&ab) && ab.state == State.CHANNEL_OPEN && ab.pending_count == 1 && ab.pending[0].handle == a2);
}

// ---------- handshake_timeout ----------
fn void handshake_timeout() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	ulong d;
	assert(!m.next_deadline(&d));
	m.connect(URL, at(1000))!!;
	assert(m.next_deadline(&d) && d == 11000);
	m.handle_timeout(at(10999))!!;
	assert(m.state == State.HEL_SENT);
	assert(@fails(m.handle_timeout(at(11000)), TIMEOUT));
	assert(m.state == State.FAILED && m.failure == TIMEOUT && next_kind(&m) == EventKind.FAILED);
	Machine o;                                                                              // the OPN has its own deadline
	o.init(mem, test_config());
	defer o.free();
	o.connect(URL, at(0))!!;
	eat(&o);
	o.feed(s.ack(), at(9000))!!;
	assert(o.next_deadline(&d) && d == 19000);
	o.handle_timeout(at(18999))!!;
	assert(@fails(o.handle_timeout(at(19000)), TIMEOUT));
	Machine ok;                                                                             // no handshake deadline once the channel is open
	ok.init(mem, test_config());
	defer ok.free();
	FakeServer t = fake_server();
	open_channel(&ok, &t, 0, 60000);
	assert(ok.next_deadline(&d) && d == 45000);
}

// ---------- request table ----------
fn void requests_unknown_id_never_reaches_another() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	uint a = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	uint b = m.send_raw(tmem, at(1), nodeid_num(0, 631), {})!!;
	assert(a != b && m.pending_count == 2);
	assert(@fails(m.feed(s.msg(77, a, 1), at(2)), REQUEST_ID_UNKNOWN));
	Event e;
	while (m.poll_event(&e))
	{
		if (e.kind == EventKind.RESPONSE) assert(e.response.kind == ResponseKind.SERVICE_FAULT && (uint)e.response.header.service_result == 0x80AE0000, "only the failure answer");
	}
}

fn void requests_timeout_and_late_answer() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	uint h = m.send_raw(tmem, at(100), nodeid_num(0, 631), {})!!;
	ulong d;
	assert(m.next_deadline(&d) && d == 1100);
	m.handle_timeout(at(1099))!!;
	assert(no_events(&m));
	m.handle_timeout(at(1100))!!;
	Event e;
	assert(m.poll_event(&e) && e.response.handle == h && e.response.local_timeout && (uint)e.response.header.service_result == 0x800A0000);
	assert(m.pending_count == 0 && m.state == State.CHANNEL_OPEN);
	m.feed(s.msg(2, h, 1), at(1200))!!;                                                     // the late answer is dropped quietly
	assert(no_events(&m) && m.state == State.CHANNEL_OPEN);
}

fn void requests_ids_and_limits() @test
{
	Config c = test_config();
	c.limits.max_outstanding_requests = 3;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.send_raw(tmem, at(0), nodeid_num(0, 631), {})!!;
	m.send_raw(tmem, at(0), nodeid_num(0, 631), {})!!;
	m.send_raw(tmem, at(0), nodeid_num(0, 631), {})!!;
	assert(@fails(m.send_raw(tmem, at(0), nodeid_num(0, 631), {}), TOO_MANY_PENDING));
	assert(m.pending_count == 3);
	// an id that is still outstanding is skipped when the counter comes around
	uint taken = m.pending[0].request_id;
	m.next_request_id = taken;
	assert(m.alloc_request_id() != taken);
	assert(@fails(m.send_raw(tmem, at(0), nodeid_num(0, 631), {}), TOO_MANY_PENDING));
	Machine early;
	early.init(mem, c);
	defer early.free();
	assert(@fails(early.send_raw(tmem, at(0), nodeid_num(0, 631), {}), BAD_STATE));
}

// ---------- chunking of requests ----------
fn void requests_large_service_is_chunked() @test
{
	Machine m;
	m.init(mem, test_config());
	defer m.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	eat(&m);
	m.feed(s.ack(8192, 8192), at(0))!!;
	eat(&m);
	m.feed(s.opn_response(1, 1, 7, 1, 3600000), at(0))!!;
	(void)next_kind(&m);
	char[] body = alloc::alloc_array(tmem, char, 30000);
	m.send_raw(tmem, at(1), nodeid_num(0, 631), body)!!;
	ChunkReader r = new_reader(8192);
	defer r.free();
	r.feed(m.pending_output())!!;
	Message got = pull(&r);
	assert(got.type == MsgType.MSG && got.body.len == 4 + 29 + 30000);
}
