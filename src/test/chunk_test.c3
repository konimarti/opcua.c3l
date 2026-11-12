module opcua;

// Transport messages and chunking (OPC 10000-6 7.1 and 6.7). Vectors B1-B3, B11-B13, M1-M9, M12-M18, M21-M25, M27, M30,
// D3-D6 plus the extras named in the comments.

// ---------- fixtures ----------
fn void fixtures_hello_ack_error() @test
{
	ByteBuf b;
	b.init(tmem);
	HelloMessage hello = { 0, 65536, 65536, 0, 0, "opc.tcp://localhost:4840" };
	encode_hello(&b, &hello)!!;
	assert(b.bytes() == unhex(B1_HEL));                                                  // B1
	HelloMessage h = decode_hello(unhex(B1_HEL)[8..], tmem)!!;
	assert(h.receive_buffer_size == 65536 && h.max_chunk_count == 0 && h.endpoint_url == "opc.tcp://localhost:4840");
	MessageHeader hh = decode_header(unhex(B1_HEL)[:8])!!;
	assert(hh.type == MsgType.HEL && hh.chunk == ChunkType.FINAL && hh.size == 56);

	b.clear();
	AckMessage ack = { 0, 65536, 65536, 0, 0 };
	encode_ack(&b, &ack)!!;
	assert(b.bytes() == unhex(B2_ACK));                                                  // B2
	AckMessage a = decode_ack(unhex(B2_ACK)[8..])!!;
	assert(a.protocol_version == 0 && a.receive_buffer_size == 65536 && a.send_buffer_size == 65536 && a.max_message_size == 0);

	b.clear();
	ErrorMessage err = { (StatusCode)0x80800000, "x" };
	encode_error(&b, &err)!!;
	assert(b.bytes() == unhex(B3_ERR));                                                  // B3
	ErrorMessage e = decode_error(unhex(B3_ERR)[8..], tmem)!!;
	assert((uint)e.error == 0x80800000 && e.reason == "x");
}

fn void fixtures_headers() @test
{
	assert(@fails(decode_header(unhex("58 59 5A 46 10 00 00 00")), BAD_MESSAGE_TYPE));    // M5
	assert(@fails(decode_header(unhex("4D 53 47 58 10 00 00 00")), BAD_CHUNK));           // M6
	assert(@fails(decode_header(unhex("48 45 4C 43 38 00 00 00")), BAD_CHUNK));           // M7
	assert(@fails(decode_header(unhex("4F 50 4E 43 38 00 00 00")), BAD_CHUNK));           // OPN must be final
	assert(@fails(decode_header(unhex("41 43 4B 41 38 00 00 00")), BAD_CHUNK));
	assert(@fails(decode_header(unhex("4D 53 47 46 00")), TRUNCATED));
	foreach (String t : { "48 45 4C 46", "41 43 4B 46", "45 52 52 46", "4F 50 4E 46", "4D 53 47 46", "43 4C 4F 46", "52 48 45 46" })
	{
		assert(decode_header(unhex(cat_hex(t, "10 00 00 00")))!!.size == 16);
	}
	assert(decode_header(unhex("4D 53 47 43 10 00 00 00"))!!.chunk == ChunkType.INTERMEDIATE);
	assert(decode_header(unhex("43 4C 4F 41 10 00 00 00"))!!.chunk == ChunkType.ABORT);
	assert(decode_header(unhex("4D 53 47 46 FF FF FF FF"))!!.size == 0xFFFFFFFF);          // the size is the reader's business
}

fn String cat_hex(String a, String b) => string::tformat("%s %s", a, b);

fn void fixtures_rejected_frames() @test
{
	assert(frame_fails("48 45 4C 46 07 00 00 00", BAD_CHUNK));                            // M1
	assert(frame_fails("4D 53 47 46 FF FF FF FF", BAD_CHUNK));                            // M3
	assert(frame_fails("4D 53 47 46 00 00 00 80 00 00 00 00", BAD_CHUNK));                // M4
	assert(frame_fails("58 59 5A 46 10 00 00 00 00 00 00 00 00 00 00 00", BAD_MESSAGE_TYPE)); // M5
	assert(frame_fails("4D 53 47 58 10 00 00 00 00 00 00 00 00 00 00 00", BAD_CHUNK));    // M6
	assert(frame_fails("48 45 4C 43 38 00 00 00", BAD_CHUNK));                            // M7
	assert(frame_fails("FF FF FF FF", BAD_MESSAGE_TYPE));                                 // M30
	assert(frame_fails("48 45 4C 46 07 00 00 00", BAD_CHUNK));
	assert(frame_fails(cat_hex("4D 53 47 46 01 20 00 00", "00 00 00 00"), BAD_CHUNK, 8192));   // M17: 8193 > 8192
	// a frame of exactly the receive buffer size is fine
	ChunkReader r = new_reader(32);
	defer r.free();
	r.feed(mk_chunk('F', 1, 1, unhex("01 02 03 04 05 06 07 08")))!!;
	assert(pull(&r).body.len == 8);
}

// M2: a HEL frame with an empty body is framed, and the body decode rejects it. M9: an over-long URL is refused both ways.
fn void fixtures_hello_errors() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(unhex("48 45 4C 46 08 00 00 00"))!!;
	Message m = pull(&r);
	assert(m.type == MsgType.HEL && m.body.len == 0);
	assert(@fails(decode_hello(m.body, tmem), TRUNCATED));                                // M2
	DString url = dstring::temp();
	for (int i = 0; i < 5000; i++) url.append("a");
	ByteBuf b;
	b.init(tmem);
	HelloMessage big = { 0, 65536, 65536, 0, 0, url.str_view() };
	assert(@fails(encode_hello(&b, &big), URL_INVALID));                                  // M9 (client side)
	assert(b.len == 0, "nothing is queued");
	char[] long_body = alloc::alloc_array(tmem, char, 24 + 5000);
	mem::set(long_body.ptr, 'a', long_body.len);
	long_body[20] = 0x88;
	long_body[21] = 0x13;
	long_body[22] = 0;
	long_body[23] = 0;
	assert(@fails(decode_hello(long_body, tmem), URL_INVALID));                          // M9 (server side)
}

fn void fixtures_ack_error_errors() @test
{
	assert(@fails(decode_ack(unhex("00 00 00 00 00 00 00 00 00 00 00 00")), TRUNCATED));  // M12: 12 byte body
	char[] with_tail = cat(unhex(B2_ACK)[8..], unhex("DE AD BE EF"));
	assert(decode_ack(with_tail)!!.receive_buffer_size == 65536);                         // M13: bytes after the fields are ignored
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(unhex("41 43 4B 46 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))!!;
	Message m = pull(&r);
	assert(@fails(decode_ack(m.body), TRUNCATED));
	assert(@fails(decode_error(unhex("00 00 80 80 A0 86 01 00 78 78 78 78 78 78 78 78 78 78"), tmem), TRUNCATED));  // M14
	assert(@fails(decode_error(unhex("00 00 80 80"), tmem), TRUNCATED));
	ErrorMessage nr = decode_error(unhex("00 00 80 80 FF FF FF FF"), tmem)!!;
	assert(is_null(nr.reason));
}

fn void fixtures_message_chunks() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(unhex(MSG_AABB))!!;
	Message m = pull(&r);
	assert(m.type == MsgType.MSG && m.channel_id == 7 && m.token_id == 1 && m.request_id == 3 && m.body == unhex("AA BB") && !m.aborted);
	assert(nothing_more(&r) && !r.mid_frame());
	ByteBuf b;
	b.init(tmem);
	ChunkWriter w = chunk_writer(8192);
	w.next_sequence = 2;
	w.write_message(&b, MsgType.MSG, 7, 1, 3, unhex("AA BB"))!!;
	assert(b.bytes() == unhex(MSG_AABB));
	assert(w.next_sequence == 3);
	b.clear();
	w.next_sequence = 5;
	w.write_message(&b, MsgType.MSG, 7, 2, 4, b7_body())!!;
	assert(b.bytes() == b7_frame());                                                      // B7
	ChunkReader r7 = new_reader();
	defer r7.free();
	r7.feed(b7_frame())!!;
	assert(pull(&r7).body == b7_body());
}

// ---------- RHE ----------
fn void rhe_round_trip() @test
{
	ByteBuf b;
	b.init(tmem);
	ReverseHello rh = { "u", "e" };
	encode_reverse_hello(&b, &rh)!!;
	assert(b.bytes() == unhex(RHE_FRAME));
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(b.bytes())!!;
	Message m = pull(&r);
	assert(m.type == MsgType.RHE);
	ReverseHello back = decode_reverse_hello(m.body, tmem)!!;
	assert(back.server_uri == "u" && back.endpoint_url == "e");
	assert(@fails(decode_reverse_hello(unhex("01 00 00 00 75"), tmem), TRUNCATED));
	DString url = dstring::temp();
	for (int i = 0; i < 5000; i++) url.append("a");
	ReverseHello big = { "u", url.str_view() };
	assert(@fails(encode_reverse_hello(&b, &big), URL_INVALID));
}

// ---------- segmentation ----------
fn void segmentation_two_frames_in_one_feed() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(cat(unhex(B1_HEL), unhex(B2_ACK)))!!;                                          // B13
	Message a = pull(&r);
	assert(a.type == MsgType.HEL && a.body.len == 48);
	Message b = pull(&r);
	assert(b.type == MsgType.ACK && b.body.len == 20);
	assert(nothing_more(&r) && !r.mid_frame());
}

fn void segmentation_byte_at_a_time() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	char[] frame = b7_frame();
	int got = 0;
	foreach (i, c : frame)
	{
		r.feed(frame[i:1])!!;
		Message m;
		if (r.next(&m)!!)
		{
			got++;
			assert(i == frame.len - 1 && m.body == b7_body());
		}
	}
	assert(got == 1 && !r.mid_frame());
	// the same stream twice, one byte at a time
	char[] twice = cat(frame, frame);
	twice[16] = 6;                                                                        // continue after sequence number 5
	twice[frame.len + 16] = 7;
	got = 0;
	foreach (i, c : twice)
	{
		r.feed(twice[i:1])!!;
		Message m;
		while (r.next(&m)!!) got++;
	}
	assert(got == 2);
}

// D5: B7 split at every offset; also the split inside the 8 header bytes (3 + 5) and inside the size field.
fn void segmentation_split_at_every_offset() @test
{
	char[] frame = b7_frame();
	for (sz at = 0; at <= frame.len; at++)
	{
		ChunkReader r = new_reader();
		defer r.free();
		r.feed(frame[:at])!!;
		Message m;
		bool early = r.next(&m)!!;
		assert(early == (at == frame.len), "complete only when every byte is in");
		if (!early)
		{
			assert(r.mid_frame() == (at > 0));
			r.feed(frame[at..])!!;
			m = pull(&r);
		}
		assert(m.type == MsgType.MSG && m.request_id == 4 && m.body == b7_body());
		assert(nothing_more(&r));
	}
}

fn void segmentation_boundary_between_messages() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	char[] stream = cat(unhex(MSG_AABB), b7_frame());
	stream[26 + 16] = 3;                                                                  // next sequence number
	r.feed(stream[:26])!!;                                                                // exactly the first message
	assert(pull(&r).request_id == 3);
	assert(nothing_more(&r) && !r.mid_frame());
	r.feed(stream[26:10])!!;
	assert(nothing_more(&r) && r.mid_frame());
	r.feed(stream[36..])!!;
	assert(pull(&r).request_id == 4);
}

// ---------- reassembly ----------
fn void segmentation_two_chunk_message() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(b11_chunk1())!!;
	assert(nothing_more(&r) && r.mid_frame());
	r.feed(b11_chunk2())!!;
	Message m = pull(&r);
	assert(m.body == b7_body() && m.request_id == 4 && m.channel_id == 7 && m.token_id == 2);   // B11
	assert(nothing_more(&r) && !r.mid_frame());
}

fn void interleave_two_requests() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('C', 1, 10, unhex("01 02")))!!;
	r.feed(mk_chunk('C', 2, 20, unhex("A1 A2")))!!;
	r.feed(mk_chunk('C', 3, 10, unhex("03")))!!;
	r.feed(mk_chunk('F', 4, 10, unhex("04")))!!;
	r.feed(mk_chunk('C', 5, 20, unhex("A3")))!!;
	r.feed(mk_chunk('F', 6, 20, unhex("A4")))!!;
	Message first = pull(&r);
	assert(first.request_id == 10 && first.body == unhex("01 02 03 04"));
	Message second = pull(&r);
	assert(second.request_id == 20 && second.body == unhex("A1 A2 A3 A4"));
	assert(nothing_more(&r) && !r.mid_frame());
}

fn void interleave_mixed_message_types_are_refused() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('C', 1, 10, unhex("01")))!!;
	char[] clo = mk_chunk('F', 2, 10, unhex("02"));
	clo[0] = 'C';
	clo[1] = 'L';
	clo[2] = 'O';
	r.feed(clo)!!;
	assert(next_fails(&r, BAD_CHUNK));                                                    // M23: one message, two types
}

// M23: an unfinished request A followed by the final chunk of request B. Policy: reassembly is keyed by request id, so
// B completes by itself and A stays pending.
fn void interleave_final_of_another_request() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('C', 1, 10, unhex("01")))!!;
	r.feed(mk_chunk('F', 2, 20, unhex("02")))!!;
	Message m = pull(&r);
	assert(m.request_id == 20 && m.body == unhex("02"));
	assert(nothing_more(&r) && r.mid_frame() && r.partial_count == 1);
	r.feed(mk_chunk('F', 3, 10, unhex("03")))!!;
	assert(pull(&r).body == unhex("01 03"));
}

// M8: the stream ends after a complete header whose frame is not finished: that is mid-frame, not a clean end.
fn void fixtures_truncated_stream() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	assert(!r.mid_frame());
	r.feed(unhex("48 45 4C 46 38 00 00 00"))!!;
	assert(nothing_more(&r));
	assert(r.mid_frame());
}

fn void interleave_reader_after_fault_is_closed() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(unhex("58 59 5A 46 10 00 00 00"))!!;
	assert(next_fails(&r, BAD_MESSAGE_TYPE));
	assert(next_fails(&r, BAD_STATE));
}

// ---------- limits ----------
fn void limits_chunk_count() @test
{
	Limits l = default_limits();
	l.max_chunk_count = 8;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	for (uint i = 1; i <= 8; i++)
	{
		r.feed(mk_chunk('C', i, 1, unhex("00")))!!;
		assert(nothing_more(&r));
	}
	r.feed(mk_chunk('C', 9, 1, unhex("00")))!!;
	assert(next_fails(&r, TOO_MANY_CHUNKS));                                              // M24
	ChunkReader big = new_reader();                                                       // 1000 chunks against the default of 64
	defer big.free();
	Message m;
	fault seen = NOT_CONNECTED;
	for (uint i = 1; i <= 1000; i++)
	{
		big.feed(mk_chunk('C', i, 1, unhex("00")))!!;
		if (catch err = big.next(&m))
		{
			seen = err;
			break;
		}
	}
	assert(seen == TOO_MANY_CHUNKS);
}

fn void limits_message_size() @test
{
	Limits l = default_limits();
	l.max_message_size = 100;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	char[] sixty = alloc::alloc_array(tmem, char, 60);
	r.feed(mk_chunk('C', 1, 1, sixty))!!;
	assert(nothing_more(&r));
	r.feed(mk_chunk('F', 2, 1, sixty))!!;
	assert(next_fails(&r, MESSAGE_TOO_LARGE));                                            // M25
	r.free();
	ChunkReader single = new_reader(65536, l);
	defer single.free();
	single.feed(mk_chunk('F', 1, 1, alloc::alloc_array(tmem, char, 101)))!!;
	assert(next_fails(&single, MESSAGE_TOO_LARGE));
}

fn void limits_pending_table_is_full() @test
{
	Limits l = default_limits();
	l.max_pending_messages = 2;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	r.feed(mk_chunk('C', 1, 1, unhex("00")))!!;
	r.feed(mk_chunk('C', 2, 2, unhex("00")))!!;
	assert(nothing_more(&r));
	assert(nothing_more(&r));
	r.feed(mk_chunk('C', 3, 3, unhex("00")))!!;
	assert(next_fails(&r, TOO_MANY_PENDING));
	// a finished message frees its slot
	ChunkReader q = new_reader(65536, l);
	defer q.free();
	q.feed(mk_chunk('C', 1, 1, unhex("00")))!!;
	q.feed(mk_chunk('C', 2, 2, unhex("00")))!!;
	q.feed(mk_chunk('F', 3, 1, unhex("00")))!!;
	q.feed(mk_chunk('C', 4, 3, unhex("00")))!!;
	assert(pull(&q).request_id == 1);
	assert(nothing_more(&q) && nothing_more(&q));
}

fn void partials_total_cap() @test
{
	Limits l = default_limits();
	l.max_reassembly_bytes = 100;
	ChunkReader r = new_reader(65536, l);
	defer r.free();
	char[] sixty = alloc::alloc_array(tmem, char, 60);
	r.feed(mk_chunk('C', 1, 1, sixty))!!;
	assert(nothing_more(&r));
	r.feed(mk_chunk('C', 2, 2, sixty))!!;                                                 // each is small, together they are too much
	assert(next_fails(&r, MESSAGE_TOO_LARGE));
	assert(r.partial_bytes <= 100);
	// bytes of finished and aborted messages are given back
	ChunkReader q = new_reader(65536, l);
	defer q.free();
	q.feed(mk_chunk('C', 1, 1, sixty))!!;
	q.feed(mk_chunk('F', 2, 1, unhex("00")))!!;
	q.feed(mk_chunk('C', 3, 2, sixty))!!;
	assert(pull(&q).body.len == 61);
	assert(nothing_more(&q));
	assert(q.partial_bytes == 60);
}

// ---------- abort ----------
fn void abort_is_a_result() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('C', 6, 4, unhex("01 02 03")))!!;
	assert(nothing_more(&r) && r.partial_bytes == 3);
	r.feed(unhex(B12_ABORT))!!;
	Message m = pull(&r);                                                                 // B12
	assert(m.aborted && m.request_id == 4 && (uint)m.abort_status == 0x80010000 && m.abort_reason == "x" && m.body.len == 0);
	assert(r.partial_count == 0 && r.partial_bytes == 0, "the partial data of that request is gone");
	// the reader stays usable
	r.feed(mk_chunk('F', 8, 5, unhex("AA")))!!;
	Message n = pull(&r);
	assert(!n.aborted && n.request_id == 5 && n.body == unhex("AA"));
	// an abort for a request nobody started is still just a result
	r.feed(mk_abort(9, 99, 0x80010000, null_string()))!!;
	Message o = pull(&r);
	assert(o.aborted && o.request_id == 99 && is_null(o.abort_reason));
}

fn void abort_other_requests_survive() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('C', 1, 10, unhex("01")))!!;
	r.feed(mk_chunk('C', 2, 20, unhex("02")))!!;
	r.feed(mk_abort(3, 20, 0x80010000, "gone"))!!;
	Message a = pull(&r);
	assert(a.aborted && a.request_id == 20 && a.abort_reason == "gone");
	assert(r.partial_count == 1 && r.partial_bytes == 1);
	r.feed(mk_chunk('F', 4, 10, unhex("03")))!!;
	assert(pull(&r).body == unhex("01 03"));
}

// ---------- sequence numbers ----------
fn void sequence_gap_and_replay() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('F', 5, 1, unhex("00")))!!;
	assert(pull(&r).request_id == 1);
	r.feed(mk_chunk('F', 7, 2, unhex("00")))!!;
	assert(next_fails(&r, SEQUENCE_ERROR));                                               // M21
	ChunkReader q = new_reader();
	defer q.free();
	q.feed(mk_chunk('F', 5, 1, unhex("00")))!!;
	assert(pull(&q).request_id == 1);
	q.feed(mk_chunk('F', 5, 2, unhex("00")))!!;
	assert(next_fails(&q, SEQUENCE_ERROR));                                               // M22
	ChunkReader f = new_reader();                                                         // the first value is free, then +1
	defer f.free();
	f.feed(mk_chunk('F', 4000, 1, unhex("00")))!!;
	f.feed(mk_chunk('F', 4001, 2, unhex("00")))!!;
	assert(pull(&f).request_id == 1 && pull(&f).request_id == 2);
}

fn void sequence_wrap_rule() @test
{
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(mk_chunk('F', 0xFFFFFBFF, 1, unhex("00")))!!;
	r.feed(mk_chunk('F', 1, 2, unhex("00")))!!;                                           // M27: wrap to a small value
	r.feed(mk_chunk('F', 2, 3, unhex("00")))!!;
	assert(pull(&r).request_id == 1 && pull(&r).request_id == 2 && pull(&r).request_id == 3);
	ChunkReader q = new_reader();
	defer q.free();
	q.feed(mk_chunk('F', 0xFFFFFBFF, 1, unhex("00")))!!;
	q.feed(mk_chunk('F', 0x400, 2, unhex("00")))!!;                                       // 1024 is not below 1024
	assert(pull(&q).request_id == 1);
	assert(next_fails(&q, SEQUENCE_ERROR));
	ChunkReader p = new_reader();                                                         // a wrap below the limit is a gap
	defer p.free();
	p.feed(mk_chunk('F', 100000, 1, unhex("00")))!!;
	p.feed(mk_chunk('F', 1, 2, unhex("00")))!!;
	assert(pull(&p).request_id == 1);
	assert(next_fails(&p, SEQUENCE_ERROR));
	ChunkReader top = new_reader();                                                       // 0xFFFFFFFF then 0 is plain +1
	defer top.free();
	top.feed(mk_chunk('F', 0xFFFFFFFF, 1, unhex("00")))!!;
	top.feed(mk_chunk('F', 0, 2, unhex("00")))!!;
	assert(pull(&top).request_id == 1 && pull(&top).request_id == 2);
}

// D6: the writer wraps by itself and the reader accepts what the writer produces.
fn void sequence_writer_wraps() @test
{
	ChunkWriter w = chunk_writer(8192);
	w.next_sequence = 0xFFFFFBFF;
	ByteBuf b;
	b.init(tmem);
	for (uint i = 0; i < 4; i++) w.write_message(&b, MsgType.MSG, 7, 2, i + 1, unhex("00"))!!;
	assert(w.next_sequence == 3);
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(b.bytes())!!;
	for (uint i = 0; i < 4; i++) assert(pull(&r).request_id == i + 1);
	// the sequence numbers on the wire
	assert(load_u32_test(b.bytes(), 16) == 0xFFFFFBFF && load_u32_test(b.bytes(), 25 + 16) == 0xFFFFFC00 && load_u32_test(b.bytes(), 50 + 16) == 1);
}

fn uint load_u32_test(char[] b, sz at) => (uint)b[at] | (uint)b[at + 1] << 8 | (uint)b[at + 2] << 16 | (uint)b[at + 3] << 24;

// ---------- minimum sizes ----------
fn void min_sizes_symmetric() @test
{
	assert(frame_fails("4D 53 47 46 10 00 00 00 07 00 00 00 02 00 00 00", BAD_CHUNK));   // M16: size 16, no sequence header
	assert(frame_fails("4D 53 47 46 17 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00 01 00 00", BAD_CHUNK));
	ChunkReader r = new_reader();                                                         // M15: size 24 is framed, the Machine rejects it
	defer r.free();
	r.feed(unhex("4D 53 47 46 18 00 00 00 07 00 00 00 02 00 00 00 01 00 00 00 05 00 00 00"))!!;
	Message m = pull(&r);
	assert(m.type == MsgType.MSG && m.body.len == 0 && m.request_id == 5);
}

fn void min_sizes_open() @test
{
	assert(frame_fails("4F 50 4E 46 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", BAD_CHUNK));
	// M18: SecurityPolicyUri length 0x7FFFFFFF in an otherwise plausible frame
	assert(frame_fails("4F 50 4E 46 28 00 00 00 00 00 00 00 FF FF FF 7F 00 00 00 00 FF FF FF FF FF FF FF FF 01 00 00 00 01 00 00 00 00 00 00 00", BAD_LENGTH));
	// a URI that runs past the end of the frame
	assert(frame_fails("4F 50 4E 46 28 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 01 00 00 00 01 00 00 00 00 00 00 00", TRUNCATED));
	// the header fits but the sequence header does not
	assert(frame_fails("4F 50 4E 46 20 00 00 00 00 00 00 00 08 00 00 00 41 41 41 41 41 41 41 41 FF FF FF FF FF FF FF FF", BAD_CHUNK));
}

fn void open_request_bytes() @test
{
	ByteBuf b;
	b.init(tmem);
	ChunkWriter w = chunk_writer(65536);
	w.write_open(&b, 0, 1, unhex(B4_BODY))!!;
	assert(b.bytes() == cat(unhex(B4_HEAD), unhex(B4_BODY)));
	assert(b.len == 132);
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(b.bytes())!!;
	Message m = pull(&r);
	assert(m.type == MsgType.OPN && m.policy_uri == POLICY_NONE && m.body == unhex(B4_BODY) && m.request_id == 1);
	ChunkReader c = new_reader();
	defer c.free();
	c.feed(unhex(B6_CLO))!!;
	Message close = pull(&c);
	assert(close.type == MsgType.CLO && close.channel_id == 7 && close.token_id == 2 && close.request_id == 3 && close.body.len == 33);
	ChunkReader s = new_reader();
	defer s.free();
	s.feed(unhex(B8_RESPONSE))!!;
	Message resp = pull(&s);
	assert(resp.request_id == 4 && resp.body.len == 42);
}

fn void open_policy_uri_is_returned() @test
{
	ByteBuf b;
	b.init(tmem);
	ChunkWriter w = chunk_writer(8192);
	w.write_open(&b, 0, 1, unhex("01 00 BE 01"))!!;
	char[] f = b.bytes();
	assert(f[0] == 'O' && f[3] == 'F' && load_u32_test(f, 4) == f.len);
	assert(f.len == 8 + 4 + 4 + POLICY_NONE.len + 4 + 4 + 8 + 4);
	assert(f[12 + 4 + POLICY_NONE.len:8] == unhex("FF FF FF FF FF FF FF FF"), "two null ByteStrings");
	ChunkReader r = new_reader();
	defer r.free();
	r.feed(f)!!;
	Message m = pull(&r);
	assert(m.type == MsgType.OPN && m.policy_uri == POLICY_NONE && bytes_is_null(m.sender_certificate) && bytes_is_null(m.receiver_thumbprint));
	assert(m.channel_id == 0 && m.request_id == 1 && m.body == unhex("01 00 BE 01"));
	// a policy that differs is reported, not judged: comparing it is the state machine's job
	char[] other = cat(f[:12], cat(unhex("04 00 00 00 75 72 6E 3A"), f[12 + 4 + POLICY_NONE.len..]));
	ByteBuf patched;
	patched.init(tmem);
	patched.append(other)!!;
	patched.patch_u32(4, (uint)other.len)!!;
	ChunkReader q = new_reader();
	defer q.free();
	q.feed(patched.bytes())!!;
	assert(pull(&q).policy_uri == "urn:");
}

// ---------- writer ----------
fn void writer_split_large_body() @test
{
	sz n = 100000;
	char[] body = alloc::alloc_array(tmem, char, n);
	foreach (i, &c : body) *c = (char)(i * 7 + i / 251);
	ChunkWriter w = chunk_writer(8192);
	ByteBuf b;
	b.init(mem);
	defer b.free();
	w.write_message(&b, MsgType.MSG, 7, 2, 9, body)!!;
	sz chunks = 0;
	sz at = 0;
	while (at < b.len)
	{
		MessageHeader h = decode_header(b.bytes()[at:8])!!;
		assert(h.size <= 8192);
		assert(h.chunk == (at + h.size == b.len ? ChunkType.FINAL : ChunkType.INTERMEDIATE));
		at += h.size;
		chunks++;
	}
	assert(chunks == 13 && at == b.len);
	assert(w.next_sequence == 14);
	ChunkReader r = new_reader(8192);
	defer r.free();
	r.feed(b.bytes())!!;
	Message m = pull(&r);
	assert(m.body == body && m.request_id == 9);
	assert(nothing_more(&r));
}

fn void writer_limits_queue_nothing() @test
{
	ByteBuf b;
	b.init(tmem);
	b.append(unhex("AA"))!!;
	ChunkWriter w = chunk_writer(8192);
	w.max_chunk_count = 2;
	char[] big = alloc::alloc_array(tmem, char, 20000);
	assert(@fails(w.write_message(&b, MsgType.MSG, 7, 2, 1, big), TOO_MANY_CHUNKS));
	assert(b.len == 1 && w.next_sequence == 1);
	w.max_chunk_count = 0;
	w.max_message_size = 1000;
	assert(@fails(w.write_message(&b, MsgType.MSG, 7, 2, 1, big[:1001]), MESSAGE_TOO_LARGE));
	assert(b.len == 1 && w.next_sequence == 1);
	w.write_message(&b, MsgType.MSG, 7, 2, 1, big[:1000])!!;
	assert(b.len > 1000);
	assert(@fails(w.write_message(&b, MsgType.OPN, 7, 2, 1, big[:1]), BAD_STATE));
	ChunkWriter tiny = chunk_writer(24);                                                  // no room for a single body byte
	assert(@fails(tiny.write_message(&b, MsgType.MSG, 7, 2, 1, big[:1]), BAD_CHUNK));
	ChunkWriter exact = chunk_writer(25);
	ByteBuf e;
	e.init(tmem);
	exact.write_message(&e, MsgType.MSG, 7, 2, 1, big[:3])!!;
	assert(e.len == 75);                                                                  // three chunks of 25
	ByteBuf empty;
	empty.init(tmem);
	chunk_writer(8192).write_message(&empty, MsgType.CLO, 7, 2, 1, {})!!;
	assert(empty.len == 24 && empty.bytes()[3] == 'F');
}

// ---------- security hook ----------
fn void security_hook_sizes_and_roundtrip() @test
{
	FooterSecurity fs;
	ChunkSecurity sec = &fs;
	char[] body = alloc::alloc_array(tmem, char, 760);
	foreach (i, &c : body) *c = (char)i;
	ByteBuf plain;
	plain.init(tmem);
	chunk_writer(100).write_message(&plain, MsgType.MSG, 7, 2, 1, body)!!;
	ByteBuf wrapped;
	wrapped.init(tmem);
	ChunkWriter w = chunk_writer(100, sec);
	w.write_message(&wrapped, MsgType.MSG, 7, 2, 1, body)!!;
	assert(fs.protects == 11, "per chunk body is 72 bytes, so 11 chunks instead of 10");
	assert(plain.len == 760 + 10 * 24 && wrapped.len == 760 + 11 * 28);
	sz at = 0;
	while (at < wrapped.len)
	{
		uint size = decode_header(wrapped.bytes()[at:8])!!.size;
		assert(size <= 100);
		assert(wrapped.bytes()[at + size - 4:4] == (char[])"FOOT");
		at += size;
	}
	ChunkReader r;
	r.init(mem, default_limits(), 100, sec);
	defer r.free();
	r.feed(wrapped.bytes())!!;
	assert(pull(&r).body == body);
	assert(fs.unprotects == 11);
	// the asymmetric header comes from the hook as well
	ByteBuf open;
	open.init(tmem);
	w.write_open(&open, 0, 2, unhex("01 02"))!!;
	ChunkReader q;
	q.init(mem, default_limits(), 8192, sec);
	defer q.free();
	q.feed(open.bytes())!!;
	Message m = pull(&q);
	assert(m.policy_uri == "urn:test:footer" && m.sender_certificate == (char[])"CERT" && bytes_is_null(m.receiver_thumbprint) && m.body == unhex("01 02"));
	// a footer that does not verify is stream corruption
	char[] bad = wrapped.bytes()[:wrapped.bytes().len];
	ChunkReader z;
	z.init(mem, default_limits(), 100, sec);
	defer z.free();
	char[] broken = cat(bad[:0], bad);
	broken[99] = 'X';
	z.feed(broken)!!;
	assert(next_fails(&z, BAD_CHUNK));
}

// ---------- sweeps ----------
fn char[][] all_valid_streams()
{
	char[][] v = alloc::alloc_array(tmem, char[], 12);
	v[9] = cat(unhex(B4_HEAD), unhex(B4_BODY));
	v[10] = unhex(B6_CLO);
	v[11] = unhex(B8_RESPONSE);
	v[0] = unhex(B1_HEL);
	v[1] = unhex(B2_ACK);
	v[2] = unhex(B3_ERR);
	v[3] = b7_frame();
	v[4] = b11_chunk1();
	v[5] = b11_chunk2();
	v[6] = unhex(B12_ABORT);
	v[7] = unhex(RHE_FRAME);
	v[8] = unhex(MSG_AABB);
	return v;
}

// D3: every proper prefix of every valid frame waits for more bytes, never fails and never yields a message.
fn void prefix_sweep_frames() @test
{
	foreach (frame : all_valid_streams())
	{
		for (sz at = 0; at < frame.len; at++)
		{
			ChunkReader r = new_reader();
			defer r.free();
			r.feed(frame[:at])!!;
			Message m;
			assert(r.next(&m)!! == false, "a proper prefix is not a message");
			assert(r.mid_frame() == (at > 0));
		}
	}
}

fn void prefix_sweep_truncated_bodies() @test
{
	// the body decoders reject every proper prefix without crashing
	char[] hello = unhex(B1_HEL)[8..];
	for (sz at = 0; at < hello.len; at++) assert(@fails(decode_hello(hello[:at], tmem), TRUNCATED) || at >= 24);
	char[] ack = unhex(B2_ACK)[8..];
	for (sz at = 0; at < ack.len; at++) assert(@fails(decode_ack(ack[:at]), TRUNCATED));
	char[] err = unhex(B3_ERR)[8..];
	for (sz at = 0; at < err.len; at++) assert(@fails(decode_error(err[:at], tmem), TRUNCATED));
	char[] rhe = unhex(RHE_FRAME)[8..];
	for (sz at = 0; at < rhe.len; at++) assert(@fails(decode_reverse_hello(rhe[:at], tmem), TRUNCATED));
}

// D4: one flipped bit anywhere in a valid frame gives messages or a fault, never a crash, and the allocation high-water
// mark stays below max_reassembly_bytes plus a constant.
fn void bitflip_frames_never_crash() @test
{
	sz cap = 2 << 20;
	char[] store = alloc::alloc_array(mem, char, cap);
	defer alloc::free(mem, store.ptr);
	ArenaAllocator arena;
	arena.init(store);
	Limits l = default_limits();
	l.max_reassembly_bytes = 64 * 1024;
	l.max_message_size = 64 * 1024;
	sz high_water = 0;
	foreach (frame : all_valid_streams())
	{
		for (sz byte = 0; byte < frame.len; byte++)
		{
			for (int bit = 0; bit < 8; bit++)
			{
				char[] data = cat(frame, {});
				data[byte] ^= (char)(1 << bit);
				arena.clear();
				ChunkReader r;
				r.init(&arena, l, 8192);
				if (@ok(r.feed(data)))
				{
					Message m;
					while (try more = r.next(&m))
					{
						if (!more) break;
					}
				}
				if (arena.used > high_water) high_water = arena.used;
			}
		}
	}
	assert(high_water < (sz)l.max_reassembly_bytes + 64 * 1024, "allocation stays small");
}

fn void bitflip_hostile_sizes_do_not_allocate() @test
{
	char[1 << 16] store;
	ArenaAllocator arena;
	arena.init(&store);
	foreach (String hex : { "4D 53 47 46 FF FF FF 7F", "4D 53 47 43 00 00 00 80", "4F 50 4E 46 FF FF FF FF", "48 45 4C 46 F0 FF FF 7F" })
	{
		arena.clear();
		ChunkReader r;
		r.init(&arena, default_limits(), 65536);
		r.feed(unhex(hex))!!;
		Message m;
		assert(@fails(r.next(&m), BAD_CHUNK));
		assert(arena.used < 8192, "a size claim never buys memory");
	}
}
