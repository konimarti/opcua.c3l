module opcua;

// Read, Write and Call on an active session and the response path. Vectors B7, B8, B9, M28, M81, M82, M83, M95, M97.

struct Rig
{
	Machine m;
	FakeServer s;
	DynamicArenaAllocator arena;    // receives the decoded responses; released as a whole
}

fn void Rig.start(&self, Config c, String session_pl = "")
{
	self.m.init(mem, c);
	self.s = fake_server();
	self.arena.init(mem, 4096);
	open_active(&self.m, &self.s, session_pl);
	eat(&self.m);
}

fn void Rig.stop(&self)
{
	self.m.free();
	self.arena.free();
}

fn ReadValueId[] one_node(uint id = 2258)
{
	ReadValueId[] n = alloc::alloc_array(tmem, ReadValueId, 1);
	n[0] = { .node_id = nodeid_num(0, id), .attribute_id = ATTRIBUTE_VALUE };
	return n;
}

fn Response take_response(Machine* m)
{
	Event e;
	assert(m.poll_event(&e) && e.kind == EventKind.RESPONSE, "a RESPONSE event is expected");
	return e.response;
}

// ---------- read_bytes (B7, B8) ----------
fn void read_bytes() @test
{
	Rig r;
	Config c = session_config();
	c.request_timeout_ms = 5000;
	r.start(c);
	defer r.stop();
	// the numbers of the vector: token 2, sequence 5, request id 4, handle 4, session token ns0;i=10000
	r.m.token_id = 2;
	r.m.writer.next_sequence = 5;
	r.m.next_request_id = 4;
	r.m.next_handle = 4;
	r.m.auth_token = nodeid_num(0, 10000);
	uint h = r.m.send_read(&r.arena, at(0), one_node(), 0.0)!!;
	assert(h == 4);
	assert(r.m.pending_output() == b7_frame());                                           // B7
	eat(&r.m);
	r.s.seq = 6;
	r.m.reader.last_sequence = 5;
	char[] answer = r.s.msg(4, 4, 2, ID_READ_RESPONSE, READ_PAYLOAD);
	assert(answer == unhex(B8_RESPONSE), "the scripted server reproduces the vector");
	r.m.feed(answer, at(10))!!;                                                            // B8
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.READ && resp.handle == 4 && !resp.local_timeout);
	assert(status_is_good(resp.header.service_result) && resp.header.request_handle == 4);
	assert(resp.values.len == 1 && resp.values[0].has_value && resp.values[0].value.type == INT32 && resp.values[0].value.scalar.i32 == 42);
	assert(r.m.pending_count == 0 && no_events(&r.m));
}

// ---------- servicefault (B9) ----------
fn void servicefault() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	r.m.token_id = 2;
	r.m.next_request_id = 9;
	r.m.next_handle = 9;
	uint h = r.m.send_read(&r.arena, at(0), one_node(), 0.0)!!;
	eat(&r.m);
	r.s.seq = 7;
	r.m.reader.last_sequence = 6;
	char[] fault_frame = r.s.service_fault(9, 9, 2, 0x800B0000);
	assert(fault_frame == unhex("4D 53 47 46 34 00 00 00 07 00 00 00 02 00 00 00 07 00 00 00 09 00 00 00 01 00 8D 01 00 00 00 00 00 00 00 00 09 00 00 00 00 00 0B 80 00 FF FF FF FF 00 00 00"));
	r.m.feed(fault_frame, at(1))!!;                                                              // B9
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.SERVICE_FAULT && resp.handle == h && (uint)resp.header.service_result == 0x800B0000);
	assert((uint)r.m.last_status == 0x800B0000 && r.m.state == State.ACTIVE, "a ServiceFault answers one request and nothing else");
	// trailing bytes behind a ServiceFault
	uint h2 = r.m.send_read(&r.arena, at(2), one_node(), 0.0)!!;
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	char[] bad = r.s.msg(p.request_id, h2, 2, ID_SERVICE_FAULT_HEX, "AA", 0x800B0000);
	assert(@fails(r.m.feed(bad, at(3)), BAD_RESPONSE));
}

// ---------- write_gate ----------
fn void write_gate() @test
{
	Rig r;
	r.start(session_config());                                                             // allow_write is false
	defer r.stop();
	WriteValue[1] w = { write_value(nodeid_str(2, "Setpoint"), variant_i32(7)) };
	assert(@fails(r.m.send_write(&r.arena, at(1), &w), WRITE_NOT_ALLOWED));
	Variant[1] args = { variant_i32(1) };
	CallMethodRequest[1] calls = { { .object_id = nodeid_num(2, 1), .method_id = nodeid_num(2, 2), .input_arguments = &args } };
	assert(@fails(r.m.send_call(&r.arena, at(1), &calls), WRITE_NOT_ALLOWED));
	assert(r.m.pending_output().len == 0 && r.m.pending_count == 0, "nothing was queued");
	assert(r.m.state == State.ACTIVE);
	assert(@fails(r.m.send_write(&r.arena, at(1), {}), WRITE_NOT_ALLOWED), "the gate comes before the empty check");
	// reading is not gated
	(void)r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
}

fn void write_gate_allowed() @test
{
	Rig r;
	Config c = session_config();
	c.allow_write = true;
	r.start(c);
	defer r.stop();
	WriteValue[1] w = { write_value(nodeid_str(2, "Setpoint"), variant_i32(7)) };
	assert(w[0].attribute_id == 13 && w[0].value.has_value && w[0].value.status == STATUS_GOOD && (long)w[0].value.source_ts == 0);
	uint h = r.m.send_write(&r.arena, at(1), &w)!!;
	Message wm = first_message(r.m.pending_output());
	assert(wm.body[:4] == unhex("01 00 A1 02"), "WriteRequest");
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_WRITE_RESPONSE, WRITE_PAYLOAD), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.WRITE && resp.handle == h && resp.statuses.len == 1 && resp.statuses[0] == STATUS_GOOD);
	Variant[1] args = { variant_i32(1) };
	CallMethodRequest[1] calls = { { .object_id = nodeid_num(2, 1), .method_id = nodeid_num(2, 2), .input_arguments = &args } };
	uint ch = r.m.send_call(&r.arena, at(3), &calls)!!;
	eat(&r.m);
	PendingRequest cp = r.m.pending[0];
	r.m.feed(r.s.msg(cp.request_id, ch, 1, ID_CALL_RESPONSE, CALL_PAYLOAD), at(4))!!;
	Response cr = take_response(&r.m);
	assert(cr.kind == ResponseKind.CALL && cr.calls.len == 1 && cr.calls[0].status_code == STATUS_GOOD && cr.calls[0].output_arguments.len == 0);
}

// ---------- empty_request (M81) ----------
fn void empty_request() @test
{
	Config c = session_config();
	c.allow_write = true;
	Rig r;
	r.start(c);
	defer r.stop();
	ReadValueId[] none;
	assert(@fails(r.m.send_read(&r.arena, at(1), none, 0.0), EMPTY_REQUEST));
	assert(@fails(r.m.send_write(&r.arena, at(1), {}), EMPTY_REQUEST));
	assert(@fails(r.m.send_call(&r.arena, at(1), {}), EMPTY_REQUEST));
	assert(r.m.pending_output().len == 0 && r.m.pending_count == 0);
	// M81: a request with a null node array (count -1) is decodable; the encoder of the machine never sends one
	ReadRequest empty;
	char[] bytes = enc_read_request(empty);
	assert(bytes[bytes.len - 4:4] == unhex("FF FF FF FF"));
	Decoder d = decoder(bytes, tmem);
	ReadRequest back = d.get_read_request()!!;
	assert(back.nodes_to_read.ptr == null && back.nodes_to_read.len == 0 && d.remaining() == 0);
}

// ---------- size_limits (M95) ----------
fn void size_limits() @test
{
	// the server's MaxRequestMessageSize
	Rig r;
	r.start(session_config(), session_payload(DOUBLE_60000, "", "01 01 64 00", 100));
	defer r.stop();
	ReadValueId[1] node = { { .node_id = nodeid_num(0, 2258), .attribute_id = 13, .index_range = "0:1,0:1,0:1,0:1,0:1,0:1,0:1,0:1,0:1,0:1,0:1,0:1" } };
	assert(@fails(r.m.send_read(&r.arena, at(1), &node, 0.0), MESSAGE_TOO_LARGE));         // M95
	assert(r.m.pending_output().len == 0 && r.m.pending_count == 0 && r.m.state == State.ACTIVE, "nothing written, no state change");
	(void)r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;                               // a small request still goes
	// the peer's MaxMessageSize from the ACK, with and without a session limit
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	DynamicArenaAllocator arena;
	arena.init(mem, 4096);
	defer arena.free();
	FakeServer s = fake_server();
	m.connect(URL, at(0))!!;
	eat(&m);
	m.feed(s.ack(65536, 65536, 0, 0), at(0))!!;
	eat(&m);
	m.feed(s.opn_response(1, 1, 7, 1, 3600000), at(0))!!;
	(void)next_kind(&m);
	m.open_session(identity_anonymous(), at(0))!!;
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	eat(&m);
	m.feed(s.activate_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	(void)next_kind(&m);
	m.writer.max_message_size = 100;                                                       // what the ACK announced (the ACK mapping is tested with the handshake)
	assert(m.request_size_limit() == 100);
	assert(@fails(m.send_read(&arena, at(1), &node, 0.0), MESSAGE_TOO_LARGE));
	assert(m.pending_output().len == 0);
	m.session_max_request = 90;
	assert(m.request_size_limit() == 90, "the smaller of the two");
	m.session_max_request = 5000;
	assert(m.request_size_limit() == 100);
	m.writer.max_message_size = 0;
	assert(m.request_size_limit() == 5000, "a zero is ignored");
	m.session_max_request = 0;
	assert(m.request_size_limit() == 0);
	(void)m.send_read(&arena, at(1), &node, 0.0)!!;
}

// ---------- handle_mismatch, wrong_type (M82, M83), trailing_bytes ----------
fn void handle_mismatch() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	PendingRequest p = r.m.pending[0];
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h + 3, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(2)), BAD_RESPONSE));
	assert(r.m.state == State.FAILED);
}

fn void wrong_type() @test
{
	String[3] types = { ID_READ_REQUEST, "01 00 FF FF", ID_WRITE_RESPONSE };
	foreach (t : types)
	{
		Rig r;
		r.start(session_config());
		defer r.stop();
		uint h = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
		PendingRequest p = r.m.pending[0];
		assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, t, READ_PAYLOAD), at(2)), BAD_RESPONSE));        // M82, M83 and a response of another service
		Event e;
		assert(r.m.poll_event(&e) && e.kind == EventKind.RESPONSE && (uint)e.response.header.service_result == 0x80AE0000, "the request is failed");
	}
}

fn void trailing_bytes_and_count_mismatch() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	PendingRequest p = r.m.pending[0];
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, ID_READ_RESPONSE, string::tformat("%s AA", READ_PAYLOAD)), at(2)), BAD_RESPONSE));
	Rig two;
	two.start(session_config());
	defer two.stop();
	ReadValueId[2] nodes = { { .node_id = nodeid_num(0, 1), .attribute_id = 13 }, { .node_id = nodeid_num(0, 2), .attribute_id = 13 } };
	uint h2 = two.m.send_read(&two.arena, at(1), &nodes, 0.0)!!;
	PendingRequest q = two.m.pending[0];
	assert(@fails(two.m.feed(two.s.msg(q.request_id, h2, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(2)), BAD_RESPONSE), "one result for two nodes");
	// a Bad ServiceResult carries no results and is delivered as it is
	Rig bad;
	bad.start(session_config());
	defer bad.stop();
	uint h3 = bad.m.send_read(&bad.arena, at(1), one_node(), 0.0)!!;
	PendingRequest b = bad.m.pending[0];
	bad.m.feed(bad.s.msg(b.request_id, h3, 1, ID_READ_RESPONSE, "00 00 00 00 00 00 00 00", 0x80010000), at(2))!!;
	Response resp = take_response(&bad.m);
	assert(resp.kind == ResponseKind.READ && (uint)resp.header.service_result == 0x80010000 && resp.values.len == 0);
	assert(bad.m.state == State.ACTIVE);
	// a truncated body is a violation of the stream
	Rig cut;
	cut.start(session_config());
	defer cut.stop();
	uint h4 = cut.m.send_read(&cut.arena, at(1), one_node(), 0.0)!!;
	PendingRequest c = cut.m.pending[0];
	assert(@fails(cut.m.feed(cut.s.msg(c.request_id, h4, 1, ID_READ_RESPONSE, "01 00 00 00 01 06"), at(2)), TRUNCATED));
}

// ---------- late_reply (M28), unsolicited (M97), timeout_flag ----------
fn void late_reply_and_timeout_flag() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(100), one_node(), 0.0)!!;
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	r.m.handle_timeout(at(1100))!!;
	Response resp = take_response(&r.m);
	assert(resp.handle == h && resp.local_timeout && (uint)resp.header.service_result == 0x800A0000 && resp.kind == ResponseKind.SERVICE_FAULT);
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(1200))!!;       // M28: ignored
	assert(no_events(&r.m) && r.m.state == State.ACTIVE);
}

fn void timeout_flag_remote_is_not_local() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	// a server's own Bad_Timeout is not marked as local
	uint h2 = r.m.send_read(&r.arena, at(2000), one_node(), 0.0)!!;
	PendingRequest q = r.m.pending[0];
	r.m.feed(r.s.service_fault(q.request_id, h2, 1, 0x800A0000), at(2100))!!;
	Response remote = take_response(&r.m);
	assert(!remote.local_timeout && (uint)remote.header.service_result == 0x800A0000);
}

fn void unsolicited() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	r.m.feed(r.s.msg(77, 5, 1, ID_PUBLISH_RESPONSE, "00 00 00 00"), at(1))!!;               // M97: a Publish answer without a subscription
	r.m.feed(r.s.msg(78, 5, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(2))!!;                   // a known response nobody asked for
	assert(no_events(&r.m) && r.m.state == State.ACTIVE);
	assert(@fails(r.m.feed(r.s.msg(79, 5, 1, "01 00 FF FF", ""), at(3)), REQUEST_ID_UNKNOWN), "an unknown type with an unknown id is a violation");
}

// ---------- out_of_order ----------
fn void out_of_order() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h1 = r.m.send_read(&r.arena, at(1), one_node(1), 0.0)!!;
	uint h2 = r.m.send_read(&r.arena, at(1), one_node(2), 0.0)!!;
	eat(&r.m);
	PendingRequest p1 = r.m.pending[0];
	PendingRequest p2 = r.m.pending[1];
	r.m.feed(r.s.msg(p2.request_id, h2, 1, ID_READ_RESPONSE, READ_PAYLOAD), at(2))!!;
	r.m.feed(r.s.msg(p1.request_id, h1, 1, ID_READ_RESPONSE, "01 00 00 00 01 06 2B 00 00 00 00 00 00 00"), at(3))!!;
	Response first = take_response(&r.m);
	Response second = take_response(&r.m);
	assert(first.handle == h2 && first.values[0].value.scalar.i32 == 42);
	assert(second.handle == h1 && second.values[0].value.scalar.i32 == 43);
	assert(r.m.pending_count == 0);
}

fn void abort_completes_one_request() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h1 = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	uint h2 = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	eat(&r.m);
	PendingRequest p1 = r.m.pending[0];
	char[] abort = mk_abort(r.s.seq, p1.request_id, 0x80010000, "x");
	abort[8] = 7;
	abort[12] = 1;
	r.m.feed(abort, at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.handle == h1 && (uint)resp.header.service_result == 0x80010000 && no_events(&r.m));
	assert(r.m.pending_count == 1 && r.m.pending[0].handle == h2 && r.m.state == State.ACTIVE);
}

fn void services_need_an_active_session() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	assert(@fails(m.send_read(tmem, at(1), one_node(), 0.0), BAD_STATE), "no session yet");
	m.open_session(identity_anonymous(), at(1))!!;
	assert(@fails(m.send_read(tmem, at(1), one_node(), 0.0), BAD_STATE), "the session is not active yet");
}
