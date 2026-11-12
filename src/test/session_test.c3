module opcua;

// Session handling of the machine: CreateSession, ActivateSession, identity rules, response checks, loss of the session,
// keep-alive, CloseSession. Vectors M90, M91, M92 and the extras named in the comments. The scripted server answers from
// hand-written hex templates.

// Opens the channel (channel 7, token 1) and a session; the machine ends ACTIVE with the SESSION_ACTIVE event drained.
fn void open_active(Machine* m, FakeServer* s, String session_pl = "", Identity id = identity_anonymous(), ulong t = 0)
{
	open_channel(m, s, t);
	m.open_session(id, at(t))!!;
	eat(m);
	PendingRequest p = m.pending[0];
	m.feed(s.create_session_response(p.request_id, p.handle, 1, session_pl), at(t))!!;
	assert(m.state == State.ACTIVATING);
	eat(m);
	PendingRequest a = m.pending[0];
	m.feed(s.activate_response(a.request_id, a.handle, 1), at(t))!!;
	assert(m.state == State.ACTIVE);
	assert(next_kind(m) == EventKind.SESSION_ACTIVE);
}

fn Config session_config()
{
	Config c = test_config();
	c.nonce_seed = 0x1234;
	return c;
}

// ---------- session_bytes ----------
fn void session_bytes_create_session() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_anonymous(), at(0))!!;
	assert(m.state == State.SESSION_CREATING);
	Message cm = first_message(m.pending_output());
	assert(cm.type == MsgType.MSG && cm.channel_id == 7 && cm.token_id == 1);
	String head = string::tformat("01 00 CD 01 %s %s %s 02 %s 01 00 00 00 %s %s %s %s %s %s 20 00 00 00",
		request_header_hex("00 00", 2, 1000), str_hex("urn:opcua.c3l:client"), str_hex("urn:opcua.c3l"), str_hex("opcua.c3l client"),
		NULL4, NULL4, NULL4, NULL4, str_hex(URL), str_hex("opcua.c3l session"));
	String tail = string::tformat("%s 00 00 00 00 80 4F 32 41 00 00 00 00", NULL4);         // certificate null, 1 200 000 ms, no response limit
	char[] expected_head = unhex(head);
	char[] expected_tail = unhex(tail);
	char[] body = cm.body;
	assert(body.len == expected_head.len + 32 + expected_tail.len);
	assert(body[:expected_head.len] == expected_head);
	assert(body[expected_head.len + 32..] == expected_tail);
	char[] nonce = body[expected_head.len:32];
	bool all_zero = true;
	foreach (c : nonce)
	{
		if (c != 0) all_zero = false;
	}
	assert(!all_zero, "the nonce comes from the seed");
	// the same seed gives the same nonce, another seed another one
	Machine same;
	same.init(mem, session_config());
	defer same.free();
	FakeServer s2 = fake_server();
	open_channel(&same, &s2);
	same.open_session(identity_anonymous(), at(0))!!;
	assert(first_message(same.pending_output()).body == body);
	Config other = session_config();
	other.nonce_seed = 99;
	Machine diff;
	diff.init(mem, other);
	defer diff.free();
	FakeServer s3 = fake_server();
	open_channel(&diff, &s3);
	diff.open_session(identity_anonymous(), at(0))!!;
	assert(first_message(diff.pending_output()).body != body);
	assert(@fails(m.open_session(identity_anonymous(), at(0)), BAD_STATE), "one session at a time");
}

fn void session_bytes_activate_anonymous() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_anonymous(), at(0))!!;
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	assert(m.state == State.ACTIVATING && m.have_session);
	Message am = first_message(m.pending_output());
	String expected = string::tformat("01 00 D3 01 %s %s %s %s 01 00 41 01 01 08 00 00 00 %s %s %s",
		request_header_hex("01 01 65 00", 3, 1000), "FF FF FF FF FF FF FF FF", NULL4, NULL4, str_hex("anon"), NULL4, NULL4);
	assert(am.body == unhex(expected));
}

fn void session_bytes_activate_user_name() @test
{
	Config c = session_config();
	c.allow_cleartext_password = true;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_username("alice", "s3cret"), at(0))!!;
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	assert(m.state == State.ACTIVATING);
	Message am = first_message(m.pending_output());
	String token = string::tformat("%s %s 06 00 00 00 73 33 63 72 65 74 %s", str_hex("user"), str_hex("alice"), NULL4);
	sz token_len = unhex(token).len;
	String expected = string::tformat("01 00 D3 01 %s %s %s %s 01 00 44 01 01 %s %s %s %s",
		request_header_hex("01 01 65 00", 3, 1000), "FF FF FF FF FF FF FF FF", NULL4, NULL4, le32((uint)token_len), token, NULL4, NULL4);
	assert(am.body == unhex(expected));
}

// ---------- identity_rules ----------
fn void identity_rules_cleartext_password() @test
{
	Machine m;
	m.init(mem, session_config());                                                         // allow_cleartext_password is false
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	assert(@fails(m.open_session(identity_username("a", "b"), at(0)), SECURITY_UNSUPPORTED));
	assert(m.pending_output().len == 0 && m.state == State.CHANNEL_OPEN && m.pending_count == 0, "nothing queued");
	Identity cert = { .type = UserTokenType.CERTIFICATE };
	assert(@fails(m.open_session(cert, at(0)), SECURITY_UNSUPPORTED));
	m.open_session(identity_anonymous(), at(0))!!;                                         // the refusal changed nothing
	assert(m.state == State.SESSION_CREATING);
}

// M91: a user name policy that names a security policy needs an encrypted password: refused even with the opt-in.
fn void identity_rules_policy_with_encryption() @test
{
	Config c = session_config();
	c.allow_cleartext_password = true;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_username("alice", "pw"), at(0))!!;
	eat(&m);
	String eps = string::tformat("01 00 00 00 %s", endpoint_hex(str_hex("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")));
	assert(@fails(m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1, session_payload(DOUBLE_60000, eps)), at(0)), SECURITY_UNSUPPORTED));
	assert(m.state == State.FAILED && m.pending_output().len == 0, "no ActivateSession with the password");
}

fn void identity_rules_endpoint_and_policy_selection() @test
{
	// no endpoint with mode None and policy None
	Machine a;
	a.init(mem, session_config());
	defer a.free();
	FakeServer s = fake_server();
	open_channel(&a, &s);
	a.open_session(identity_anonymous(), at(0))!!;
	eat(&a);
	String signed_only = string::tformat("01 00 00 00 %s", endpoint_hex(NULL4, str_hex("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"), 2));
	assert(@fails(a.feed(s.create_session_response(a.pending[0].request_id, a.pending[0].handle, 1, session_payload(DOUBLE_60000, signed_only)), at(0)), BAD_STATE));
	// the endpoint offers no user name policy
	Config c = session_config();
	c.allow_cleartext_password = true;
	Machine b;
	b.init(mem, c);
	defer b.free();
	FakeServer t = fake_server();
	open_channel(&b, &t);
	b.open_session(identity_username("u", "p"), at(0))!!;
	eat(&b);
	String no_user = string::tformat("01 00 00 00 %s", endpoint_hex(NULL4, NONE_URI_FULL, 1, false));
	assert(@fails(b.feed(t.create_session_response(b.pending[0].request_id, b.pending[0].handle, 1, session_payload(DOUBLE_60000, no_user)), at(0)), BAD_STATE));
	// find_endpoint and find_token_policy on their own
	UserTokenPolicy[1] pol = { { .policy_id = "p", .token_type = UserTokenType.ANONYMOUS } };
	EndpointDescription[2] eps;
	eps[0] = { .security_mode = MessageSecurityMode.SIGN, .security_policy_uri = POLICY_NONE };
	eps[1] = { .security_mode = MessageSecurityMode.NONE, .security_policy_uri = POLICY_NONE, .user_identity_tokens = &pol };
	EndpointDescription* found = find_endpoint(&eps, MessageSecurityMode.NONE, POLICY_NONE);
	assert(found == &eps[1] && find_endpoint(&eps, MessageSecurityMode.SIGN_AND_ENCRYPT, POLICY_NONE) == null);
	assert(find_token_policy(found, UserTokenType.ANONYMOUS) == &pol[0] && find_token_policy(found, UserTokenType.USER_NAME) == null);
}

// ---------- session_response_checks (M92) ----------
fn void session_response_checks_timeout() @test
{
	String[4] timeouts = { DOUBLE_NAN, DOUBLE_ZERO, DOUBLE_MINUS, DOUBLE_INF };
	foreach (t : timeouts)
	{
		Machine m;
		m.init(mem, session_config());
		defer m.free();
		FakeServer s = fake_server();
		open_active(&m, &s, session_payload(t));
		assert(m.session_timeout_ms == 60000, "a nonsense RevisedSessionTimeout becomes the local default");
	}
	Machine ok;
	ok.init(mem, session_config());
	defer ok.free();
	FakeServer s = fake_server();
	open_active(&ok, &s, session_payload(DOUBLE_90000, "", "01 01 64 00", 4096));
	assert(ok.session_timeout_ms == 90000 && ok.session_max_request == 4096);
	assert(ok.endpoints.len == 1 && ok.endpoints[0].user_identity_tokens.len == 2);
	assert(nodeid_equals(ok.auth_token, nodeid_num(1, 101)));
}

fn void session_response_checks_null_session_id() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_anonymous(), at(0))!!;
	eat(&m);
	assert(@fails(m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1, session_payload(DOUBLE_60000, "", "00 00")), at(0)), BAD_RESPONSE));
	assert(m.state == State.FAILED && !m.have_session);
	Machine bad;                                                                           // a Bad ServiceResult in the answer
	bad.init(mem, session_config());
	defer bad.free();
	FakeServer t = fake_server();
	open_channel(&bad, &t);
	bad.open_session(identity_anonymous(), at(0))!!;
	eat(&bad);
	char[] frame = t.msg(bad.pending[0].request_id, bad.pending[0].handle, 1, ID_CREATE_SESSION_RESPONSE, session_payload(), 0x80010000);
	assert(@fails(bad.feed(frame, at(0)), SERVICE_FAULT));
	assert((uint)bad.last_status == 0x80010000);
}

fn void session_response_checks_activation() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_anonymous(), at(0))!!;
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	eat(&m);
	PendingRequest a = m.pending[0];
	assert(@fails(m.feed(s.activate_response(a.request_id, a.handle, 1, 0x80200000), at(0)), SERVICE_FAULT), "a Bad ServiceResult of ActivateSession fails the machine");
	assert((uint)m.last_status == 0x80200000 && m.state == State.FAILED);
	Machine t;                                                                             // an ActivateSession that never answers
	t.init(mem, session_config());
	defer t.free();
	FakeServer u = fake_server();
	open_channel(&t, &u);
	t.open_session(identity_anonymous(), at(0))!!;
	eat(&t);
	assert(@fails(t.handle_timeout(at(1000)), TIMEOUT));
}

// ---------- session_lost (M90) ----------
fn void session_lost_from_a_service_fault() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s);
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	ReadValueId[1] nodes = { { .node_id = nodeid_num(0, 2258), .attribute_id = 13 } };
	uint h = m.send_read(&arena, at(1), &nodes, 0.0)!!;
	eat(&m);
	PendingRequest p = m.pending[0];
	// M90: BadSessionNotActivated (0x80270000) from the server
	assert(@fails(m.feed(s.service_fault(p.request_id, h, 1, 0x80270000), at(2)), SESSION_LOST));
	assert((uint)m.last_status == 0x80270000 && m.state == State.FAILED && m.failure == SESSION_LOST);
	Event e;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE && (uint)e.response.header.service_result == 0x80AE0000);
	assert(m.poll_event(&e) && e.kind == EventKind.FAILED && no_events(&m));
}

fn void session_lost_from_a_normal_header() @test
{
	uint[3] codes = { 0x80250000, 0x80260000, 0x80270000 };
	foreach (code : codes)
	{
		Machine m;
		m.init(mem, session_config());
		defer m.free();
		FakeServer s = fake_server();
		open_active(&m, &s);
		DynamicArenaAllocator arena;
		arena.init(mem, 4096);
		defer arena.free();
		ReadValueId[1] nodes = { { .node_id = nodeid_num(0, 2258), .attribute_id = 13 } };
		uint h = m.send_read(&arena, at(1), &nodes, 0.0)!!;
		PendingRequest p = m.pending[0];
		assert(@fails(m.feed(s.msg(p.request_id, h, 1, ID_READ_RESPONSE, "00 00 00 00 00 00 00 00", code), at(2)), SESSION_LOST));
		assert(m.failure == SESSION_LOST);
	}
}

// ---------- keep-alive ----------
fn void keepalive_idle_read() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s, session_payload(DOUBLE_60000), identity_anonymous(), 1000);
	eat(&m);
	ulong d;
	assert(m.next_deadline(&d) && d == 1000 + 30000, "50% of RevisedSessionTimeout after the last activity");
	m.handle_timeout(at(30999))!!;
	assert(m.pending_output().len == 0 && m.pending_count == 0);
	m.handle_timeout(at(31000))!!;
	Message k = first_message(m.pending_output());
	assert(k.type == MsgType.MSG && m.pending_count == 1 && m.keepalive_pending);
	assert(k.body[:4] == unhex("01 00 77 02"), "a Read request");
	assert(k.body[47:4] == unhex("01 00 00 00"), "one node");
	assert(k.body[51:8] == unhex("01 00 D3 08 0D 00 00 00"), "i=2259, attribute Value");
	eat(&m);
	assert(no_events(&m));
	// the answer is consumed internally
	PendingRequest p = m.pending[0];
	m.feed(s.msg(p.request_id, p.handle, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(31100))!!;
	assert(no_events(&m) && m.pending_count == 0 && !m.keepalive_pending && m.state == State.ACTIVE);
	assert(m.next_deadline(&d) && d == 31100 + 30000, "the idle timer starts again");
	// traffic of the caller postpones it
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	ReadValueId[1] nodes = { { .node_id = nodeid_num(0, 2258), .attribute_id = 13 } };
	uint h = m.send_read(&arena, at(50000), &nodes, 0.0)!!;
	eat(&m);
	assert(m.next_deadline(&d) && d == 51000, "the request deadline comes first");
	m.feed(s.msg(m.pending[0].request_id, h, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(50100))!!;
	assert(m.next_deadline(&d) && d == 50100 + 30000);
}

fn void keepalive_failure() @test
{
	String[3] answers = { "session", "other", "silent" };
	foreach (kind : answers)
	{
		Machine m;
		m.init(mem, session_config());
		defer m.free();
		FakeServer s = fake_server();
		open_active(&m, &s);
		m.handle_timeout(at(30000))!!;
		eat(&m);
		PendingRequest p = m.pending[0];
		if (kind == "session")
		{
			assert(@fails(m.feed(s.msg(p.request_id, p.handle, 1, ID_READ_RESPONSE, "00 00 00 00 00 00 00 00", 0x80260000), at(30100)), SESSION_LOST));
		}
		else if (kind == "other")
		{
			assert(@fails(m.feed(s.msg(p.request_id, p.handle, 1, ID_READ_RESPONSE, "00 00 00 00 00 00 00 00", 0x80010000), at(30100)), SERVICE_FAULT));
			assert((uint)m.last_status == 0x80010000);
		}
		else
		{
			assert(@fails(m.handle_timeout(at(31000)), TIMEOUT), "a keep-alive that is never answered is not swallowed");
		}
		assert(m.state == State.FAILED && next_kind(&m) == EventKind.FAILED, "no RESPONSE event for the internal request");
	}
	Machine faulty;                                                                         // a ServiceFault answer
	faulty.init(mem, session_config());
	defer faulty.free();
	FakeServer t = fake_server();
	open_active(&faulty, &t);
	faulty.handle_timeout(at(30000))!!;
	eat(&faulty);
	PendingRequest q = faulty.pending[0];
	assert(@fails(faulty.feed(t.service_fault(q.request_id, q.handle, 1, 0x80270000), at(30100)), SESSION_LOST));
}

// ---------- close with a session ----------
fn void session_close_sends_close_session_then_clo() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s);
	eat(&m);
	m.close(at(10))!!;
	assert(m.state == State.CLOSING);
	Message cs = first_message(m.pending_output());
	String expected = string::tformat("01 00 D9 01 %s 01", request_header_hex("01 01 65 00", m.next_handle - 1, 1000));
	assert(cs.body == unhex(expected), "CloseSession with DeleteSubscriptions");
	eat(&m);
	assert(m.state == State.CLOSING && no_events(&m), "the channel stays open until CloseSession is answered");
	PendingRequest p = m.pending[0];
	m.feed(s.msg(p.request_id, p.handle, 1, ID_CLOSE_SESSION_RESPONSE, ""), at(20))!!;
	Message clo = first_message(m.pending_output());
	assert(clo.type == MsgType.CLO && clo.channel_id == 7);
	eat(&m);
	assert(m.state == State.CLOSED && next_kind(&m) == EventKind.CLOSED && no_events(&m));
	m.close(at(30))!!;
	assert(m.pending_output().len == 0);
}

fn void session_close_without_an_answer() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s);
	eat(&m);
	m.close(at(10))!!;
	eat(&m);
	m.handle_timeout(at(1010))!!;                                                          // CloseSession got no answer: close the channel anyway
	Message clo = first_message(m.pending_output());
	assert(clo.type == MsgType.CLO);
	eat(&m);
	assert(m.state == State.CLOSED);
	assert(next_kind(&m) == EventKind.CLOSED);
}
