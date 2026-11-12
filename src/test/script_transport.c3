module opcua;
import std::thread;
import std::time;

// A Transport double with a scripted server behind it: what the client writes is parsed with an independent reader, and
// the answers (built from the hand-written hex templates of the fake server) are queued for the next read.

struct ScriptTransport (Transport)
{
	FakeServer server;
	ChunkReader reader;
	ByteBuf inbox;
	uint token;                // token the server answers with (a renewal increments it)
	uint lifetime;
	bool silent;               // answer nothing
	bool eof_when_empty;       // read reports the end of the stream once the inbox is empty
	bool fail_browse_next;
	uint total_pages;          // 0: the default two pages; N: a browse of exactly N pages, one reference each
	uint pages_given;
	bool endless_pages;        // every BrowseNext page names another continuation point
	bool write_times_out;      // write faults with TIMEOUT     // answer a BrowseNext (not a release) with a ServiceFault
	bool closed;
	bool close_seen;           // a CLO chunk arrived
	uint release_seen;         // BrowseNext chunks with ReleaseContinuationPoints
	uint renewals_seen;
	uint requests_seen;
	uint last_type;            // type id of the last request
	ByteBuf written;           // every byte the client wrote
}

fn void ScriptTransport.start(&self, uint lifetime = 3600000)
{
	*self = {};
	self.server = fake_server();
	self.reader.init(mem, default_limits(), 65536);
	self.inbox.init(mem, 1024);
	self.written.init(mem, 1024);
	self.token = 1;
	self.lifetime = lifetime;
}

fn void ScriptTransport.stop(&self)
{
	self.reader.free();
	self.inbox.free();
	self.written.free();
}

fn void ScriptTransport.reply(&self, char[] frame) => self.inbox.append(frame)!!;

fn usz? ScriptTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (self.inbox.len == 0)
	{
		if (self.eof_when_empty) return CLOSED~;
		long ms = timeout.to_ms();
		if (ms > 5) ms = 5;
		if (ms > 0) thread::sleep_ms((uint)ms);
		return TIMEOUT~;
	}
	sz n = buf.len < self.inbox.len ? buf.len : self.inbox.len;
	mem::copy(buf.ptr, self.inbox.data.ptr, n);
	sz rest = self.inbox.len - n;
	if (rest > 0) mem::move(self.inbox.data.ptr, self.inbox.data.ptr + n, rest);
	self.inbox.len = rest;
	return (usz)n;
}

fn void? ScriptTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (self.closed) return CLOSED~;
	if (self.write_times_out) return TIMEOUT~;
	self.written.append(data)!;
	self.reader.feed(data)!;
	Message m;
	while (self.reader.next(&m)!)
	{
		if (!self.silent) self.answer(&m);
	}
}

fn void? ScriptTransport.close(&self) @dynamic
{
	self.closed = true;
}

// type id and handle of a request body
fn void request_ids(char[] body, uint* type_id, uint* handle)
{
	Decoder d = decoder(body, tmem);
	NodeId tid = d.get_nodeid()!!;
	*type_id = tid.num;
	(void)d.get_nodeid()!!;                      // AuthenticationToken
	(void)d.get_u64()!!;                         // Timestamp
	*handle = d.get_u32()!!;
}

fn void ScriptTransport.answer(&self, Message* m)
{
	self.requests_seen++;
	switch (m.type)
	{
		case HEL: self.reply(self.server.ack());
		case OPN:
			uint type_id;
			uint handle;
			request_ids(m.body, &type_id, &handle);
			uint request_type = load_u32_test(m.body, 37);
			if (request_type == 1)
			{
				self.token++;
				self.renewals_seen++;
			}
			self.reply(self.server.opn_response(m.request_id, handle, 7, self.token, self.lifetime));
		case CLO: self.close_seen = true;
		case MSG:
			uint type_id;
			uint handle;
			request_ids(m.body, &type_id, &handle);
			self.last_type = type_id;
			uint rid = m.request_id;
			FakeServer* s = &self.server;
			uint t = self.token;
			switch (type_id)
			{
				case CREATE_SESSION_REQUEST_ENCODING_ID: self.reply(s.create_session_response(rid, handle, t));
				case ACTIVATE_SESSION_REQUEST_ENCODING_ID: self.reply(s.activate_response(rid, handle, t));
				case CLOSE_SESSION_REQUEST_ENCODING_ID: self.reply(s.msg(rid, handle, t, ID_CLOSE_SESSION_RESPONSE, ""));
				case READ_REQUEST_ENCODING_ID: self.reply(s.msg(rid, handle, t, ID_READ_RESPONSE, READ_PAYLOAD));
				case WRITE_REQUEST_ENCODING_ID: self.reply(s.msg(rid, handle, t, ID_WRITE_RESPONSE, WRITE_PAYLOAD));
				case CALL_REQUEST_ENCODING_ID: self.reply(s.msg(rid, handle, t, ID_CALL_RESPONSE, CALL_PAYLOAD));
				case GET_ENDPOINTS_REQUEST_ENCODING_ID: self.reply(s.msg(rid, handle, t, ID_GET_ENDPOINTS_RESPONSE, three_endpoints()));
				case BROWSE_REQUEST_ENCODING_ID:
					self.pages_given = 1;
					String first_cp = (self.total_pages == 0 || self.total_pages > 1) ? "02 00 00 00 CC DD" : NULL4;
					self.reply(s.msg(rid, handle, t, ID_BROWSE_RESPONSE, browse_payload(first_cp, 1, ref_hex("a"))));
				case BROWSE_NEXT_REQUEST_ENCODING_ID:
					bool release = m.body[35] != 0;
					if (release)
					{
						self.release_seen++;
						self.reply(s.msg(rid, handle, t, ID_BROWSE_NEXT_RESPONSE, browse_payload(NULL4, 0, "")));
					}
					else if (self.fail_browse_next)
					{
						self.reply(s.service_fault(rid, handle, t, 0x80010000));
					}
					else if (self.total_pages > 0)
					{
						self.pages_given++;
						String cp = self.pages_given < self.total_pages ? "02 00 00 00 CC DD" : NULL4;
						self.reply(s.msg(rid, handle, t, ID_BROWSE_NEXT_RESPONSE, browse_payload(cp, 1, ref_hex("b"))));
					}
					else if (self.endless_pages)
					{
						self.reply(s.msg(rid, handle, t, ID_BROWSE_NEXT_RESPONSE, browse_payload("02 00 00 00 CC DD", 1, ref_hex("b"))));
					}
					else
					{
						self.reply(s.msg(rid, handle, t, ID_BROWSE_NEXT_RESPONSE, browse_payload(NULL4, 1, ref_hex("b"))));
					}
				default:
			}
		default:
	}
}
