module opcua;

// Regression tests for the response path, the outbox and the URL parser.

fn void fixes_late_typed_reply_with_session_lost() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(100), one_node(), 0.0)!!;
	PendingRequest p = r.m.pending[0];
	r.m.handle_timeout(at(5000))!!;
	(void)take_response(&r.m);
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, ID_READ_RESPONSE, "00 00 00 00 00 00 00 00", 0x80260000), at(5100)), SESSION_LOST));
	Rig u;
	u.start(session_config());
	defer u.stop();
	assert(@fails(u.m.feed(u.s.msg(901, 5, 1, ID_WRITE_RESPONSE, "00 00 00 00 00 00 00 00", 0x80270000), at(10)), SESSION_LOST));
	Rig ok;                                                                                  // a late typed reply with another status is still dropped
	ok.start(session_config());
	defer ok.stop();
	uint h2 = ok.m.send_read(&ok.arena, at(100), one_node(), 0.0)!!;
	PendingRequest p2 = ok.m.pending[0];
	ok.m.handle_timeout(at(5000))!!;
	(void)take_response(&ok.m);
	ok.m.feed(ok.s.msg(p2.request_id, h2, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(5100))!!;
	assert(no_events(&ok.m) && ok.m.state == State.ACTIVE);
}

fn void fixes_password_is_not_left_in_the_outbox() @test
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
	assert(contains_bytes(m.outbox.data, (char[])"s3cret"), "the request carries the password until it was handed to the transport");
	eat(&m);
	assert(!contains_bytes(m.outbox.data, (char[])"s3cret"), "the consumed output is overwritten");
}

fn bool contains_bytes(char[] hay, char[] needle)
{
	if (needle.len == 0 || hay.len < needle.len) return false;
	for (sz i = 0; i + needle.len <= hay.len; i++)
	{
		if (hay[i:needle.len] == needle) return true;
	}
	return false;
}

fn void fixes_url_user_info_and_control_characters() @test
{
	String[8] bad = { "opc.tcp://user@host", "opc.tcp://user:pw@host:4840", "opc.tcp://host name:4840", "opc.tcp://host\t:4840", "opc.tcp://[::1]@x", "opc.tcp://h\n", "opc.tcp://h:4840/p q", "opc.tcp://@h" };
	foreach (u : bad) assert(@fails(parse_endpoint_url(u), URL_INVALID), "an invalid URL is accepted");
	assert(parse_endpoint_url("opc.tcp://h:4840/a@b")!!.path == "/a@b", "an @ in the path is data");
}

// BrowseNext with ReleaseContinuationPoints answers with empty Results and DiagnosticInfos (10000-4 BrowseNext): no count check.
fn void fixes_release_answers_may_be_empty() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	char[][2] points = { unhex("AA"), unhex("BB") };
	uint h = r.m.send_browse_next(&r.arena, at(1), &points, true)!!;
	PendingRequest p = r.m.pending[0];
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_BROWSE_NEXT_RESPONSE, "00 00 00 00 00 00 00 00"), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.BROWSE_NEXT && resp.browse_results.len == 0 && r.m.state == State.ACTIVE);
	uint h2 = r.m.send_browse_next(&r.arena, at(3), &points, false)!!;                       // without release the count still matters
	PendingRequest q = r.m.pending[0];
	assert(@fails(r.m.feed(r.s.msg(q.request_id, h2, 1, ID_BROWSE_NEXT_RESPONSE, "00 00 00 00 00 00 00 00"), at(4)), BAD_RESPONSE));
}
