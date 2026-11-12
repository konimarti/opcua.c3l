module opcua;

// The redacted dump (trace_chunk): headers, type ids and sizes, never a token, a password or a raw body.

fn String traced(char[] chunk)
{
	ByteBuf b;
	b.init(tmem);
	trace_chunk(chunk, &b);
	return (String)b.bytes();
}

fn void trace_read_request_hides_the_token() @test
{
	String out = traced(b7_frame());                                                       // token ns0;i=10000
	assert(out.contains("MSG F size=93") && out.contains("channel=7 token=2 seq=5 request=4"));
	assert(out.contains("type=i=631 (ReadRequest)") && out.contains("auth=<redacted>"));
	assert(!out.contains("10000"), "the AuthenticationToken value is not printed");
	assert(!out.contains("10 27") && !out.contains("1027") && !out.contains("0x"), "nor its bytes");
	assert(out.contains("body=") && out.ends_with("\n"));
}

fn void trace_activate_session_hides_the_password() @test
{
	Config c = session_config();
	c.allow_cleartext_password = true;
	Machine m;
	m.init(mem, c);
	defer m.free();
	FakeServer s = fake_server();
	open_channel(&m, &s);
	m.open_session(identity_username("alice", "secret"), at(0))!!;
	eat(&m);
	m.feed(s.create_session_response(m.pending[0].request_id, m.pending[0].handle, 1), at(0))!!;
	char[] activate = cat(m.pending_output(), {});
	assert(activate.len > 0);
	String out = traced(activate);
	assert(out.contains("type=i=467 (ActivateSessionRequest)") && out.contains("body=<redacted>"));
	assert(!out.contains("secret") && !out.contains("alice"));
	assert(!out.contains("73 65 63 72 65 74") && !out.contains("736563726574") && !out.contains("0x"));
	assert(!out.contains("auth="), "the whole body is replaced");
	// the user name token on its own is redacted as well
	ByteBuf b;
	b.init(tmem);
	DString line = dstring::temp();
	trace_chunk_text(&line, activate);
	assert(!line.str_view().contains("secret"));
}

fn void trace_other_frames() @test
{
	assert(traced(unhex(B1_HEL)).contains("HEL F size=56 body=48 bytes"));
	assert(traced(unhex(B2_ACK)).contains("ACK F size=28"));
	assert(traced(unhex(B3_ERR)).contains("ERR F size=17"));
	String open = traced(cat(unhex(B4_HEAD), unhex(B4_BODY)));
	assert(open.contains("OPN F size=132 channel=0 policy=http://opcfoundation.org/UA/SecurityPolicy#None sender_certificate=0 bytes thumbprint=0 bytes seq=1 request=1"));
	assert(open.contains("type=i=446 (OpenSecureChannelRequest)"));
	assert(traced(unhex(B6_CLO)).contains("CLO F size=57 channel=7 token=2 seq=5 request=3 type=i=452"));
	String resp = traced(unhex(B8_RESPONSE));
	assert(resp.contains("type=i=634 (ReadResponse) body=") && !resp.contains("auth="), "a response has no token");
	assert(traced(unhex(B12_ABORT)).contains("MSG A size=33") && traced(unhex(B12_ABORT)).contains("aborted"));
	assert(traced(unhex("4D 53")).contains("<short chunk, 2 bytes>"));
	assert(traced(unhex("58 59 5A 46 10 00 00 00 00 00 00 00 00 00 00 00")).contains("<bad header"));
	assert(traced(unhex("4D 53 47 46 10 00 00 00 00 00 00 00 00 00 00 00")).contains("<short>"));
}

fn void trace_stream_splitter() @test
{
	FrameTracer t;
	t.init(mem);
	defer t.free();
	ByteBuf out;
	out.init(tmem);
	char[] stream = cat(unhex(B2_ACK), b7_frame());
	foreach (i, c : stream) t.feed(stream[i:1], &out);                                     // one byte at a time
	String text = (String)out.bytes();
	assert(text.contains("ACK F size=28 body=20 bytes\n") && text.contains("MSG F size=93") && !text.contains("10000"));
	sz lines = 0;
	foreach (c : text)
	{
		if (c == '\n') lines++;
	}
	assert(lines == 2);
}
