module opcua;

// Discovery, Browse, BrowseNext, TranslateBrowsePathsToNodeIds, result validation and index ranges.
// Vectors B10, M84, M85, M86, M93 and the extras named in the comments.

fn String three_endpoints()
{
	String sec = str_hex(POLICY_BASIC256SHA256);
	return string::tformat("03 00 00 00 %s %s %s", endpoint_hex(), endpoint_hex(NULL4, sec, 2), endpoint_hex(NULL4, sec, 3));
}

// ---------- getendpoints_bytes (B10) ----------
fn void getendpoints_bytes() @test
{
	Machine m;
	Config c = session_config();
	c.request_timeout_ms = 10000;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.token_id = 2;
	m.writer.next_sequence = 5;
	m.next_request_id = 2;
	m.next_handle = 2;
	uint h = m.send_get_endpoints(tmem, at(0), URL)!!;
	assert(h == 2);
	assert(m.pending_output() == unhex(B10_GET_ENDPOINTS));                               // B10
	// discovery works with the channel alone and never carries a token, also when a session exists
	Rig r;
	r.start(session_config());
	defer r.stop();
	(void)r.m.send_get_endpoints(&r.arena, at(1), URL)!!;
	Message gm = first_message(r.m.pending_output());
	assert(gm.body[4:2] == unhex("00 00"), "a null AuthenticationToken");
	Machine early;
	early.init(mem, session_config());
	defer early.free();
	assert(@fails(early.send_get_endpoints(tmem, at(0), URL), BAD_STATE));
}

// ---------- discovery_flow ----------
fn void discovery_flow() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_get_endpoints(&r.arena, at(1), URL)!!;
	PendingRequest p = r.m.pending[0];
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_GET_ENDPOINTS_RESPONSE, three_endpoints()), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.GET_ENDPOINTS && resp.handle == h && resp.endpoints.len == 3);
	assert(resp.endpoints[1].security_mode == MessageSecurityMode.SIGN && resp.endpoints[2].security_mode == MessageSecurityMode.SIGN_AND_ENCRYPT);
	String[1] uris = { "urn:s" };
	uint h2 = r.m.send_find_servers(&r.arena, at(3), URL, &uris)!!;
	PendingRequest q = r.m.pending[0];
	String server = "01 00 00 00 01 00 00 00 73 FF FF FF FF 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF";
	r.m.feed(r.s.msg(q.request_id, h2, 1, ID_FIND_SERVERS_RESPONSE, server), at(4))!!;
	Response fs = take_response(&r.m);
	assert(fs.kind == ResponseKind.FIND_SERVERS && fs.servers.len == 1 && fs.servers[0].application_uri == "s");
	uint h3 = r.m.send_find_servers_on_network(&r.arena, at(5), 0, 10)!!;
	PendingRequest n = r.m.pending[0];
	r.m.feed(r.s.msg(n.request_id, h3, 1, ID_FIND_SERVERS_ON_NETWORK_RESPONSE, "00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 6E FF FF FF FF FF FF FF FF"), at(6))!!;
	Response fn_ = take_response(&r.m);
	assert(fn_.kind == ResponseKind.FIND_SERVERS_ON_NETWORK && fn_.servers_on_network.len == 1 && fn_.servers_on_network[0].server_name == "n");
}

// ---------- serviceunsupported_is_response ----------
fn void serviceunsupported_is_response() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_find_servers_on_network(&r.arena, at(1), 0, 10)!!;
	PendingRequest p = r.m.pending[0];
	r.m.feed(r.s.service_fault(p.request_id, h, 1, 0x800B0000), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.SERVICE_FAULT && (uint)resp.header.service_result == 0x800B0000);
	assert(r.m.state == State.ACTIVE, "not a failure of the machine");
	uint h2 = r.m.send_find_servers_on_network(&r.arena, at(3), 0, 10)!!;
	PendingRequest q = r.m.pending[0];
	r.m.feed(r.s.msg(q.request_id, h2, 1, ID_FIND_SERVERS_ON_NETWORK_RESPONSE, "00 00 00 00 00 00 00 00 FF FF FF FF", 0x80400000), at(4))!!;
	Response nr = take_response(&r.m);
	assert(nr.kind == ResponseKind.FIND_SERVERS_ON_NETWORK && (uint)nr.header.service_result == 0x80400000 && nr.servers_on_network.len == 0);
	assert(r.m.state == State.ACTIVE);
}

// ---------- browse_flow (M93) ----------
fn void browse_flow() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	BrowseDescription[1] nodes = { { .node_id = nodeid_num(0, 85), .browse_direction = BrowseDirection.FORWARD, .reference_type_id = nodeid_num(0, 33), .include_subtypes = true, .result_mask = 63 } };
	uint h = r.m.send_browse(&r.arena, at(1), &nodes, 3)!!;
	Message bm = first_message(r.m.pending_output());
	assert(bm.body[:4] == unhex("01 00 0F 02"), "BrowseRequest");
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	// the answer arrives in three chunks: two references, one more, and the third reference with the continuation point
	String refs = string::tformat("%s %s %s", ref_hex("a"), ref_hex("b"), ref_hex("c"));
	char[] whole = r.s.msg(p.request_id, h, 1, ID_BROWSE_RESPONSE, browse_payload("02 00 00 00 CC DD", 3, refs));
	char[] payload = whole[24..];
	r.s.seq--;                                                                              // `whole` was only a template
	sz third = payload.len / 3;
	r.m.feed(r.s.chunk('C', p.request_id, 1, payload[:third]), at(2))!!;
	assert(no_events(&r.m));
	r.m.feed(r.s.chunk('C', p.request_id, 1, payload[third:third]), at(2))!!;
	assert(no_events(&r.m));
	r.m.feed(r.s.chunk('F', p.request_id, 1, payload[2 * third..]), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.BROWSE && resp.browse_results.len == 1 && resp.browse_results[0].references.len == 3);
	assert(resp.browse_results[0].references[2].browse_name.name == "c" && resp.browse_results[0].continuation_point == unhex("CC DD"));
	// M93: the continuation point is data; BrowseNext continues with it
	char[][1] points = { resp.browse_results[0].continuation_point };
	uint h2 = r.m.send_browse_next(&r.arena, at(3), &points, false)!!;
	Message nm = first_message(r.m.pending_output());
	assert(nm.body[4 + 31:1] == unhex("00") && nm.body[4 + 31 + 1:4] == unhex("01 00 00 00") && nm.body[4 + 31 + 5:6] == unhex("02 00 00 00 CC DD"));
	eat(&r.m);
	PendingRequest q = r.m.pending[0];
	r.m.feed(r.s.msg(q.request_id, h2, 1, ID_BROWSE_NEXT_RESPONSE, browse_payload(NULL4, 1, ref_hex("d"))), at(4))!!;
	Response next = take_response(&r.m);
	assert(next.kind == ResponseKind.BROWSE_NEXT && next.browse_results[0].references.len == 1 && bytes_is_null(next.browse_results[0].continuation_point));
	// releasing: the request carries the flag and the answer has one empty result per point
	uint h3 = r.m.send_browse_next(&r.arena, at(5), &points, true)!!;
	Message rm = first_message(r.m.pending_output());
	assert(rm.body[4 + 31:1] == unhex("01"), "ReleaseContinuationPoints");
	eat(&r.m);
	PendingRequest t = r.m.pending[0];
	r.m.feed(r.s.msg(t.request_id, h3, 1, ID_BROWSE_NEXT_RESPONSE, browse_payload(NULL4, 0, "")), at(6))!!;
	Response rel = take_response(&r.m);
	assert(rel.kind == ResponseKind.BROWSE_NEXT && rel.browse_results.len == 1 && rel.browse_results[0].references.len == 0);
	char[][] no_points;
	assert(@fails(r.m.send_browse(&r.arena, at(7), {}, 0), EMPTY_REQUEST));
	assert(@fails(r.m.send_browse_next(&r.arena, at(7), no_points, true), EMPTY_REQUEST));
	assert(r.m.pending_output().len == 0);
}

// ---------- translate_flow ----------
fn void translate_flow() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	RelativePathElement[2] one = { { .reference_type_id = nodeid_num(0, 35), .include_subtypes = true, .target_name = { .name = "Server" } }, { .reference_type_id = nodeid_num(0, 35), .is_inverse = true, .target_name = { .ns = 2, .name = "X" } } };
	RelativePathElement[1] two = { { .reference_type_id = nodeid_num(0, 33), .target_name = { .name = "Y" } } };
	RelativePathElement[][2] paths = { &one, &two };
	uint h = r.m.send_translate(&r.arena, at(1), nodeid_num(0, 84), &paths)!!;
	Message tm = first_message(r.m.pending_output());
	assert(tm.body[:4] == unhex("01 00 2A 02"), "TranslateBrowsePathsToNodeIdsRequest");
	assert(tm.body[35:4] == unhex("02 00 00 00"), "two browse paths");
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	// RemainingPathIndex 0xFFFFFFFF: the whole path was resolved; the second path has no target
	String payload = "02 00 00 00  00 00 00 00 01 00 00 00 00 55 FF FF FF FF  00 00 34 80 FF FF FF FF  00 00 00 00";
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_TRANSLATE_RESPONSE, payload), at(2))!!;
	Response resp = take_response(&r.m);
	assert(resp.kind == ResponseKind.TRANSLATE && resp.paths.len == 2 && resp.paths[0].targets.len == 1);
	assert(resp.paths[0].targets[0].remaining_path_index == 0xFFFFFFFF && nodeid_equals(resp.paths[0].targets[0].target_id.id, nodeid_num(0, 85)));
	assert((uint)resp.paths[1].status_code == 0x80340000 && resp.paths[1].targets.len == 0);
	RelativePathElement[][] no_paths;
	assert(@fails(r.m.send_translate(&r.arena, at(3), nodeid_num(0, 84), no_paths), EMPTY_REQUEST));
}

// ---------- count_mismatch (M84) ----------
fn void count_mismatch() @test
{
	// ReadResponse with 2 results for 1 node
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(1), one_node(), 0.0)!!;
	PendingRequest p = r.m.pending[0];
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, ID_READ_RESPONSE, "02 00 00 00 01 06 2A 00 00 00 01 06 2B 00 00 00 00 00 00 00"), at(2)), BAD_RESPONSE));    // M84
	// Browse: two results for one node
	Rig b;
	b.start(session_config());
	defer b.stop();
	BrowseDescription[1] nodes = { { .node_id = nodeid_num(0, 85) } };
	uint bh = b.m.send_browse(&b.arena, at(1), &nodes, 0)!!;
	PendingRequest bp = b.m.pending[0];
	String two = "02 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00";
	assert(@fails(b.m.feed(b.s.msg(bp.request_id, bh, 1, ID_BROWSE_RESPONSE, two), at(2)), BAD_RESPONSE));
	// BrowseNext: no result for one point
	Rig n;
	n.start(session_config());
	defer n.stop();
	char[][1] points = { unhex("AA") };
	uint nh = n.m.send_browse_next(&n.arena, at(1), &points, false)!!;
	PendingRequest np = n.m.pending[0];
	assert(@fails(n.m.feed(n.s.msg(np.request_id, nh, 1, ID_BROWSE_NEXT_RESPONSE, "00 00 00 00 00 00 00 00"), at(2)), BAD_RESPONSE));
	// Translate: one result for two paths
	Rig t;
	t.start(session_config());
	defer t.stop();
	RelativePathElement[1] el = { { .reference_type_id = nodeid_num(0, 33), .target_name = { .name = "Y" } } };
	RelativePathElement[][2] paths = { &el, &el };
	uint th = t.m.send_translate(&t.arena, at(1), nodeid_num(0, 84), &paths)!!;
	PendingRequest tp = t.m.pending[0];
	assert(@fails(t.m.feed(t.s.msg(tp.request_id, th, 1, ID_TRANSLATE_RESPONSE, "01 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00"), at(2)), BAD_RESPONSE));
	// Write and Call: the count is checked as well
	Config c = session_config();
	c.allow_write = true;
	Rig w;
	w.start(c);
	defer w.stop();
	WriteValue[2] values = { write_value(nodeid_num(2, 1), variant_i32(1)), write_value(nodeid_num(2, 2), variant_i32(2)) };
	uint wh = w.m.send_write(&w.arena, at(1), &values)!!;
	PendingRequest wp = w.m.pending[0];
	assert(@fails(w.m.feed(w.s.msg(wp.request_id, wh, 1, ID_WRITE_RESPONSE, WRITE_PAYLOAD), at(2)), BAD_RESPONSE));
	Rig k;
	k.start(c);
	defer k.stop();
	Variant[1] args = { variant_i32(1) };
	CallMethodRequest[2] calls = { { .object_id = nodeid_num(2, 1), .method_id = nodeid_num(2, 2), .input_arguments = &args }, { .object_id = nodeid_num(2, 1), .method_id = nodeid_num(2, 3) } };
	uint kh = k.m.send_call(&k.arena, at(1), &calls)!!;
	PendingRequest kp = k.m.pending[0];
	assert(@fails(k.m.feed(k.s.msg(kp.request_id, kh, 1, ID_CALL_RESPONSE, CALL_PAYLOAD), at(2)), BAD_RESPONSE));
}

// ---------- limits_in_responses (M85, M86) ----------
fn void limits_in_responses_string_table() @test
{
	Machine m;
	m.init(mem, session_config());
	defer m.free();
	FakeServer s = fake_server();
	open_active(&m, &s);
	eat(&m);
	char[256] store;
	ArenaAllocator tiny;
	tiny.init(&store);
	uint h = m.send_get_endpoints(&tiny, at(1), URL)!!;
	PendingRequest p = m.pending[0];
	// M85: ResponseHeader.StringTable with 10^9 entries
	String header = string::tformat("00 00 00 00 00 00 00 00 %s 00 00 00 00 00 00 CA 9A 3B", le32(h));
	assert(@fails(m.feed(s.msg_body(p.request_id, 1, ID_GET_ENDPOINTS_RESPONSE, header), at(2)), BAD_LENGTH));
	assert(tiny.used == 0, "a length claim allocates nothing");
	assert(m.state == State.FAILED);
}

fn void limits_in_responses_truncated_browse() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	BrowseDescription[1] nodes = { { .node_id = nodeid_num(0, 85) } };
	uint h = r.m.send_browse(&r.arena, at(1), &nodes, 0)!!;
	PendingRequest p = r.m.pending[0];
	// M86: 1000 references announced, 999 and a half delivered
	DString refs = dstring::temp();
	for (int i = 0; i < 999; i++) refs.append(ref_hex("r"));
	refs.append(" 00 21 01");
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, ID_BROWSE_RESPONSE, browse_payload(NULL4, 1000, refs.str_view())), at(2)), TRUNCATED));
	assert(r.m.state == State.FAILED);
	// the arena is released as a whole by Rig.stop; the leak check of the test runner proves nothing was kept elsewhere
	Event e;
	assert(r.m.poll_event(&e) && e.kind == EventKind.RESPONSE && (uint)e.response.header.service_result == 0x80AE0000);
}

fn void limits_in_responses_array_over_limit() @test
{
	Config c = session_config();
	c.limits.max_array_length = 2;
	Rig r;
	r.start(c);
	defer r.stop();
	BrowseDescription[1] nodes = { { .node_id = nodeid_num(0, 85) } };
	uint h = r.m.send_browse(&r.arena, at(1), &nodes, 0)!!;
	PendingRequest p = r.m.pending[0];
	String refs = string::tformat("%s %s %s", ref_hex("a"), ref_hex("b"), ref_hex("c"));
	assert(@fails(r.m.feed(r.s.msg(p.request_id, h, 1, ID_BROWSE_RESPONSE, browse_payload(NULL4, 3, refs)), at(2)), BAD_LENGTH));
}

// ---------- index_range ----------
fn void index_range() @test
{
	String[12] good = { "0", "5", "1:2", "0:4294967294", "1:2,3:4", "0,0", "10:20,0:1,5", "007", "12345:12346", "0:1,2", "9:10", "4294967294" };
	foreach (g : good) assert(index_range_valid(g), "a valid index range is refused");
	String[14] bad = { "5:5", "7:3", "1:", ":2", "-1", "1:2:3", "1,,2", "a", "1 2", " 1", "1;2", "4294967295", "1:2,", "," };
	foreach (b : bad) assert(!index_range_valid(b), "an invalid index range is accepted");
	String none;
	assert(index_range_valid(none), "null is valid");
	assert(index_range_valid(""), "empty is treated like null");
	Rig r;
	Config c = session_config();
	c.allow_write = true;
	r.start(c);
	defer r.stop();
	ReadValueId[1] node = { { .node_id = nodeid_num(0, 1), .attribute_id = 13, .index_range = "3:1" } };
	assert(@fails(r.m.send_read(&r.arena, at(1), &node, 0.0), BAD_ENCODING));
	assert(r.m.pending_output().len == 0 && r.m.pending_count == 0, "refused before queueing");
	WriteValue[1] w = { write_value(nodeid_num(2, 1), variant_i32(1)) };
	w[0].index_range = "x";
	assert(@fails(r.m.send_write(&r.arena, at(1), &w), BAD_ENCODING));
	assert(r.m.pending_output().len == 0);
	node[0].index_range = "1:3,0";
	(void)r.m.send_read(&r.arena, at(1), &node, 0.0)!!;
	w[0].index_range = "0:1";
	(void)r.m.send_write(&r.arena, at(1), &w)!!;
}

// ---------- endpoint_helpers, never reconnecting (S11) ----------
fn void endpoint_helpers() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_get_endpoints(&r.arena, at(1), URL)!!;
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	r.m.feed(r.s.msg(p.request_id, h, 1, ID_GET_ENDPOINTS_RESPONSE, three_endpoints()), at(2))!!;
	Response resp = take_response(&r.m);
	EndpointDescription[] eps = resp.endpoints;
	assert(eps.len == 3);
	EndpointDescription* none = find_endpoint(eps, MessageSecurityMode.NONE, POLICY_NONE);
	EndpointDescription* sign = find_endpoint(eps, MessageSecurityMode.SIGN, POLICY_BASIC256SHA256);
	EndpointDescription* both = find_endpoint(eps, MessageSecurityMode.SIGN_AND_ENCRYPT, POLICY_BASIC256SHA256);
	assert(none == &eps[0] && sign == &eps[1] && both == &eps[2]);
	assert(find_endpoint(eps, MessageSecurityMode.SIGN, POLICY_NONE) == null);
	assert(find_endpoint(eps, MessageSecurityMode.INVALID, "") == null);
	EndpointDescription*[3] chosen = { none, sign, both };
	foreach (ep : chosen)
	{
		UserTokenPolicy* anon = find_token_policy(ep, UserTokenType.ANONYMOUS);
		UserTokenPolicy* user = find_token_policy(ep, UserTokenType.USER_NAME);
		assert(anon != null && anon.policy_id == "anon" && user != null && user.policy_id == "user");
		assert(find_token_policy(ep, UserTokenType.CERTIFICATE) == null);
	}
	// S11: the host in the answer is data; the machine opens nothing and keeps the URL it was connected with
	assert(r.m.endpoint_url == URL && r.m.state == State.ACTIVE && r.m.pending_output().len == 0);
	assert(eps[0].endpoint_url == "u" && eps[0].endpoint_url != r.m.endpoint_url);
}
