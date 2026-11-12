module opcua;

// A session loss is never hidden by the rules for late replies; the clear-text password does not outlive its use.

fn void hardening_session_lost_in_a_late_service_fault() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(100), one_node(), 0.0)!!;
	eat(&r.m);
	PendingRequest p = r.m.pending[0];
	r.m.handle_timeout(at(5000))!!;                                                         // the request timed out locally
	(void)take_response(&r.m);
	assert(@fails(r.m.feed(r.s.service_fault(p.request_id, h, 1, 0x80260000), at(5100)), SESSION_LOST));
	assert(r.m.state == State.FAILED && (uint)r.m.last_status == 0x80260000);
}

fn void hardening_session_lost_in_an_unsolicited_service_fault() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	assert(@fails(r.m.feed(r.s.service_fault(777, 5, 1, 0x80250000), at(10)), SESSION_LOST));
	assert(r.m.state == State.FAILED && r.m.failure == SESSION_LOST);
}

fn void hardening_other_late_faults_are_still_dropped() @test
{
	Rig r;
	r.start(session_config());
	defer r.stop();
	uint h = r.m.send_read(&r.arena, at(100), one_node(), 0.0)!!;
	PendingRequest p = r.m.pending[0];
	r.m.handle_timeout(at(5000))!!;
	(void)take_response(&r.m);
	r.m.feed(r.s.service_fault(p.request_id, h, 1, 0x800B0000), at(5100))!!;
	r.m.feed(r.s.service_fault(778, 5, 1, 0x800B0000), at(5200))!!;
	assert(no_events(&r.m) && r.m.state == State.ACTIVE);
}

fn void hardening_password_is_wiped_after_activation_is_queued() @test
{
	Config c = session_config();
	c.allow_cleartext_password = true;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_username("alice", "s3cret"), at(0))!!;
	char* pw = m.identity.password.ptr;
	assert(pw[0] == 's', "the copy exists until the token is built");
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	assert(m.state == State.ACTIVATING);
	for (int i = 0; i < 6; i++) assert(pw[i] == 0, "the password bytes are overwritten");
	assert(m.identity.password.len == 0);
	Message am = first_message(m.pending_output());
	assert(am.body.len > 0, "the request itself was built before the wipe");
}
