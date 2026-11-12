module opcua;

// Sans-IO core. No I/O, no threads, no clock reads: time arrives as `Now`. Time units inside the core are integer
// milliseconds (the adapter converts from the clock, so the core has no time dependency).
// Every call that can change state (connect, feed, handle_timeout, close, send_*) may queue events: drain `poll_event`
// after each one. A fault returned by `feed` or `handle_timeout` has already moved the machine to FAILED.

struct Now
{
	ulong mono_ms;     // monotonic milliseconds (timeouts, renewal)
	UaDateTime utc;    // wall clock for RequestHeader.timestamp
}

struct Config
{
	String application_uri;           // default "urn:opcua.c3l:client"
	String application_name;          // default "opcua.c3l client"
	String product_uri;               // default "urn:opcua.c3l"
	String session_name;              // default "opcua.c3l session"
	uint receive_buffer_size;         // default 65536 (>= 8192)
	uint send_buffer_size;            // default 65536
	Limits limits;
	MessageSecurityMode security_mode; // default NONE (the only mode in v1; anything else -> SECURITY_UNSUPPORTED)
	String security_policy_uri;       // default POLICY_NONE
	uint channel_lifetime_ms;         // RequestedLifetime, default 3600000 (10000-4 5.5.2)
	double session_timeout_ms;        // default 1200000
	uint request_timeout_ms;          // default 10000; TimeoutHint and local deadline
	uint handshake_timeout_ms;        // default 10000: HEL->ACK and OPN->response deadlines
	uint max_response_message_size;   // CreateSession.MaxResponseMessageSize, default 0 = no limit
	ulong nonce_seed;                 // PRNG seed for the client nonce; the adapter must fill it from OS entropy (0 gives the same nonce every time)
	bool allow_cleartext_password;    // USERNAME over policy None is refused unless set
	bool allow_write;                 // default false; Write and Call refused with WRITE_NOT_ALLOWED when false
	bool validate_utf8;               // default true; false: invalid UTF-8 is replaced by U+FFFD instead of BAD_ENCODING
	bool strict_types;                // default false; true: unknown ExtensionObject types fail with UNKNOWN_TYPE
}

fn Config default_config() => {
	.application_uri = "urn:opcua.c3l:client",
	.application_name = "opcua.c3l client",
	.product_uri = "urn:opcua.c3l",
	.session_name = "opcua.c3l session",
	.receive_buffer_size = 65536,
	.send_buffer_size = 65536,
	.limits = default_limits(),
	.security_mode = MessageSecurityMode.NONE,
	.security_policy_uri = POLICY_NONE,
	.channel_lifetime_ms = 3600000,
	.session_timeout_ms = 1200000,
	.request_timeout_ms = 10000,
	.handshake_timeout_ms = 10000,
	.validate_utf8 = true,
};

enum State
{
	IDLE,
	HEL_SENT,          // waiting for ACK
	OPN_SENT,          // waiting for OpenSecureChannelResponse
	CHANNEL_OPEN,      // discovery services allowed
	SESSION_CREATING,
	SESSION_CREATED,
	ACTIVATING,
	ACTIVE,            // session services allowed
	CLOSING,           // CloseSession sent / CLO sent
	CLOSED,
	FAILED,
}

// Identity token for ActivateSession (10000-4 5.6.3; 10000-6 7.35)
struct Identity
{
	UserTokenType type;
	String username;
	String password;   // sent as-is under policy None: refused unless Config.allow_cleartext_password
}

fn Identity identity_anonymous() => { .type = UserTokenType.ANONYMOUS };
fn Identity identity_username(String user, String pass) => { .type = UserTokenType.USER_NAME, .username = user, .password = pass };

// ---- responses ----
enum ResponseKind
{
	GET_ENDPOINTS, FIND_SERVERS, FIND_SERVERS_ON_NETWORK, BROWSE, BROWSE_NEXT,
	TRANSLATE, READ, WRITE, CALL, SERVICE_FAULT,
	RAW,                         // a service answered with its undecoded body (transport and channel tests)
}

// Tagged by `kind`: read only the member that matches.
struct Response
{
	ResponseKind kind;
	uint handle;                 // returned by the send_* call
	ResponseHeader header;
	bool local_timeout;          // true when header.service_result is our own Bad_Timeout, not the server's
	char[] raw;                  // RAW: the bytes after the ResponseHeader, allocated from the request's allocator
	union
	{
		DataValue[] values;                    // READ
		StatusCode[] statuses;                 // WRITE (results)
		CallMethodResult[] calls;              // CALL
		EndpointDescription[] endpoints;       // GET_ENDPOINTS
		ApplicationDescription[] servers;      // FIND_SERVERS
		ServerOnNetwork[] servers_on_network;  // FIND_SERVERS_ON_NETWORK
		BrowseResult[] browse_results;         // BROWSE / BROWSE_NEXT
		BrowsePathResult[] paths;              // TRANSLATE
	}
}

enum EventKind
{
	CHANNEL_OPEN,
	CHANNEL_RENEWED,
	CHANNEL_RENEW_FAILED,   // a renewal got no answer; the old token is still valid, retrying. Warning only.
	SESSION_ACTIVE,
	RESPONSE,
	CLOSED,        // orderly
	FAILED,        // fatal; Machine.failure holds the fault. Every pending request was completed first (RESPONSE, Bad_ConnectionClosed)
}

struct Event
{
	EventKind kind;
	Response response;     // RESPONSE only
}

const StatusCode STATUS_BAD_TIMEOUT = (StatusCode)0x800A0000;
const StatusCode STATUS_BAD_CONNECTION_CLOSED = (StatusCode)0x80AE0000;
const StatusCode STATUS_BAD_OUT_OF_MEMORY = (StatusCode)0x80030000;


const uint DEFAULT_CHANNEL_LIFETIME_MS = 600000;   // used when the server answers RevisedLifetime 0
const uint MIN_RENEW_INTERVAL_MS = 1000;
const uint MIN_LIFETIME_MS = 2000;                 // shorter revised lifetimes are treated as this (no renewal busy loop)
const sz MAX_REMEMBERED_IDS = 16;

// What a pending request is. The session kinds and the keep-alive are internal: no RESPONSE event is produced for them.
enum PendingKind
{
	RAW,
	READ,
	WRITE,
	CALL,
	GET_ENDPOINTS,
	FIND_SERVERS,
	FIND_SERVERS_ON_NETWORK,
	BROWSE,
	BROWSE_NEXT,
	TRANSLATE,
	CREATE_SESSION,
	ACTIVATE_SESSION,
	CLOSE_SESSION,
	KEEPALIVE,
}

fn bool is_internal(PendingKind k)
{
	switch (k)
	{
		case CREATE_SESSION:
		case ACTIVATE_SESSION:
		case CLOSE_SESSION:
		case KEEPALIVE: return true;
		default: return false;
	}
}

struct PendingRequest
{
	uint request_id;
	uint handle;
	ulong deadline;
	Allocator allocator;
	PendingKind kind;
	uint expected_id;            // encoding id of the response (0 for RAW)
	sz count;                    // number of results the response must carry (0 = no check)
}

const double DEFAULT_SESSION_TIMEOUT_MS = 60000;

struct Machine
{
	Allocator allocator;
	Config config;
	State state;
	fault failure;               // set when state == FAILED
	StatusCode last_status;      // last ERR / ServiceFault / failing ServiceResult status
	ByteBuf outbox;
	sz out_pos;                  // bytes of outbox the transport already took
	ChunkReader reader;
	ChunkWriter writer;
	ChunkSecurity security;
	String endpoint_url;
	// handshake
	ulong handshake_deadline;
	bool handshake_active;
	// channel
	uint channel_id;
	uint token_id;
	uint lifetime_ms;
	ulong token_issued_ms;
	bool have_old_token;
	uint old_token_id;
	ulong old_token_expires_ms;
	bool renew_pending;
	ulong next_renew_ms;
	ulong renew_retry_ms;
	uint open_request_id;
	uint open_handle;
	uint[16] renew_ids;
	sz renew_id_count;
	NodeId auth_token;           // null until a session exists
	// session
	DynamicArenaAllocator arena; // everything the session keeps from the server (endpoints, token) and a copy of the identity
	bool arena_ready;
	bool have_session;
	bool closing_session;        // CloseSession is out, the CLO follows its answer
	Identity identity;
	EndpointDescription[] endpoints;
	double session_timeout_ms;   // the revised timeout, with a local default for nonsense values
	uint session_max_request;    // MaxRequestMessageSize of the server, 0 = none
	ulong last_activity_ms;
	bool keepalive_pending;
	ulong nonce_state;
	// requests
	uint next_request_id;
	uint next_handle;
	PendingRequest[] pending;
	sz pending_count;
	uint[16] late_ids;           // requests that timed out: a late answer is dropped quietly
	sz late_count;
	// events
	Event[] events;
	sz event_head;
	sz event_count;
	bool events_lost;            // an event could not be queued (out of memory)
	bool failed_queued;          // a FAILED event was queued or delivered
}

fn void Machine.init(&self, Allocator allocator, Config config, ChunkSecurity security = null)
{
	*self = {};
	self.allocator = allocator;
	self.config = config;
	self.security = security;
	self.state = State.IDLE;
	self.next_request_id = 1;
	self.next_handle = 1;
	self.outbox.init(allocator, 1024);
}

fn void Machine.free(&self)
{
	self.reader.free();
	self.outbox.free();
	if (self.arena_ready) self.arena.free();
	self.arena_ready = false;
	if (self.pending.ptr != null) alloc::free(self.allocator, self.pending.ptr);
	if (self.events.ptr != null) alloc::free(self.allocator, self.events.ptr);
	if (self.endpoint_url.ptr != null) alloc::free(self.allocator, self.endpoint_url.ptr);
	self.pending = {};
	self.events = {};
	self.endpoint_url = {};
	self.pending_count = 0;
	self.event_count = 0;
}

// ---------- events ----------
fn void Machine.push_event(&self, Event e)
{
	if (self.event_head > 0 && self.event_count == 0) self.event_head = 0;
	if (self.event_head + self.event_count == self.events.len)
	{
		sz cap = self.events.len == 0 ? 8 : (self.event_count + 1) * 2;
		Event[]? fresh = alloc::alloc_array_try(self.allocator, Event, cap);
		if (catch fresh)
		{
			self.events_lost = true;                               // reported by poll_event as FAILED, never silent
			return;
		}
		for (sz i = 0; i < self.event_count; i++) fresh[i] = self.events[self.event_head + i];
		if (self.events.ptr != null) alloc::free(self.allocator, self.events.ptr);
		self.events = fresh;
		self.event_head = 0;
	}
	if (e.kind == EventKind.FAILED) self.failed_queued = true;
	self.events[self.event_head + self.event_count] = e;
	self.event_count++;
}

fn bool Machine.poll_event(&self, Event* out)
{
	if (self.event_count == 0)
	{
		if (!self.events_lost) return false;
		// An event could not be queued: the caller must not wait for it forever. The machine fails, every request that is
		// still pending is answered straight from here (no queue space needed), then FAILED follows.
		if (self.state != State.FAILED && self.state != State.CLOSED)
		{
			self.state = State.FAILED;
			self.failure = BUFFER_FULL;
			self.handshake_active = false;
			self.renew_pending = false;
		}
		if (self.pending_count > 0)
		{
			PendingRequest p = self.pending[self.pending_count - 1];
			self.pending_count--;
			Event e = { .kind = EventKind.RESPONSE };
			e.response.kind = ResponseKind.SERVICE_FAULT;
			e.response.handle = p.handle;
			e.response.header.service_result = STATUS_BAD_CONNECTION_CLOSED;
			e.response.header.request_handle = p.handle;
			*out = e;
			return true;
		}
		self.events_lost = false;
		if (self.failed_queued) return false;
		self.failed_queued = true;
		*out = { .kind = EventKind.FAILED };
		return true;
	}
	*out = self.events[self.event_head];
	self.event_head++;
	self.event_count--;
	return true;
}

fn void Machine.push_kind(&self, EventKind k) => self.push_event({ .kind = k });

// ---------- ids ----------
fn bool Machine.id_in_use(&self, uint id)
{
	for (sz i = 0; i < self.pending_count; i++)
	{
		if (self.pending[i].request_id == id) return true;
	}
	if (self.open_request_id == id && self.renew_pending) return true;
	for (sz i = 0; i < self.renew_id_count; i++)
	{
		if (self.renew_ids[i] == id) return true;
	}
	return false;
}

// RequestIds are never reused while an earlier request with that id is outstanding.
fn uint Machine.alloc_request_id(&self)
{
	while (true)
	{
		uint id = self.next_request_id;
		self.next_request_id = id == uint::max ? 1 : id + 1;
		if (id != 0 && !self.id_in_use(id)) return id;
	}
}

fn uint Machine.alloc_handle(&self)
{
	uint h = self.next_handle;
	self.next_handle = h == uint::max ? 1 : h + 1;
	return h;
}

// ---------- header helpers ----------
fn RequestHeader Machine.request_header(&self, Now now, uint handle, uint timeout_hint)
{
	return { .authentication_token = self.auth_token, .timestamp = now.utc, .request_handle = handle, .timeout_hint = timeout_hint };
}

// The ResponseHeader without the parts that point into temporary memory (diagnostics, string table, additional header).
fn ResponseHeader? read_response_header(Decoder* d) @private
{
	ResponseHeader h = d.get_response_header()!;
	h.service_diagnostics = {};
	h.string_table = {};
	h.additional_header = {};
	return h;
}

// ---------- start ----------
fn void? Machine.connect(&self, String endpoint_url, Now now)
{
	if (self.state != State.IDLE) return BAD_STATE~;
	if (self.config.security_mode != MessageSecurityMode.NONE) return SECURITY_UNSUPPORTED~;
	if (self.config.security_policy_uri.len != 0 && self.config.security_policy_uri != POLICY_NONE) return SECURITY_UNSUPPORTED~;
	if (endpoint_url.len > MAX_ENDPOINT_URL) return URL_INVALID~;
	if (self.config.receive_buffer_size < MIN_BUFFER_SIZE || self.config.send_buffer_size < MIN_BUFFER_SIZE) return BAD_LENGTH~;
	if (self.config.request_timeout_ms == 0 || self.config.handshake_timeout_ms == 0 || self.config.channel_lifetime_ms == 0) return BAD_LENGTH~;
	// Everything that can fail comes first, so a failed connect leaves the machine untouched.
	// The announced MaxMessageSize / MaxChunkCount are 0 (no limit); the local ceilings in Config.limits are enforced anyway.
	HelloMessage hello = { 0, self.config.receive_buffer_size, self.config.send_buffer_size, 0, 0, endpoint_url };
	encode_hello(&self.outbox, &hello)!;
	char[]? copy = alloc::alloc_array_try(self.allocator, char, endpoint_url.len + 1);
	if (catch err = copy)
	{
		self.outbox.clear();
		return err~;
	}
	if (endpoint_url.len > 0) mem::copy(copy.ptr, endpoint_url.ptr, endpoint_url.len);
	self.endpoint_url = (String)copy[:endpoint_url.len];
	self.reader.init(self.allocator, self.config.limits, self.config.receive_buffer_size, self.security);
	self.writer = chunk_writer(self.config.send_buffer_size, self.security);
	self.state = State.HEL_SENT;
	self.handshake_active = true;
	self.handshake_deadline = now.mono_ms + self.config.handshake_timeout_ms;
}

// ---------- OpenSecureChannel ----------
fn void? Machine.queue_open(&self, bool renew, Now now)
{
	uint rid = self.alloc_request_id();
	uint handle = self.alloc_handle();
	ByteBuf b;
	b.init(self.allocator, 128);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, OPEN_SECURE_CHANNEL_REQUEST_ENCODING_ID))!;
	OpenSecureChannelRequest req = {
		.request_header = self.request_header(now, handle, self.config.request_timeout_ms),
		.request_type = renew ? SecurityTokenRequestType.RENEW : SecurityTokenRequestType.ISSUE,
		.security_mode = self.config.security_mode,
		.requested_lifetime = self.config.channel_lifetime_ms,
	};
	e.put_open_secure_channel_request(req)!;
	self.writer.write_open(&self.outbox, self.channel_id, rid, b.bytes())!;
	if (renew)
	{
		if (self.renew_id_count == MAX_REMEMBERED_IDS)
		{
			for (sz i = 1; i < MAX_REMEMBERED_IDS; i++) self.renew_ids[i - 1] = self.renew_ids[i];
			self.renew_id_count--;
		}
		self.renew_ids[self.renew_id_count] = rid;
		self.renew_id_count++;
	}
	self.open_request_id = rid;
	self.open_handle = handle;
}

fn uint effective_lifetime(uint revised) @private => revised == 0 ? DEFAULT_CHANNEL_LIFETIME_MS : (revised < MIN_LIFETIME_MS ? MIN_LIFETIME_MS : revised);

fn void Machine.schedule_renewal(&self)
{
	ulong interval = (ulong)self.lifetime_ms * 3 / 4;
	if (interval < MIN_RENEW_INTERVAL_MS) interval = MIN_RENEW_INTERVAL_MS;
	self.next_renew_ms = self.token_issued_ms + interval;
}

fn void? Machine.on_ack(&self, Message* m, Now now)
{
	AckMessage ack = decode_ack(m.body)!;
	if (ack.protocol_version > 0) return BAD_HANDSHAKE~;
	if (ack.receive_buffer_size < MIN_BUFFER_SIZE || ack.send_buffer_size < MIN_BUFFER_SIZE) return BAD_HANDSHAKE~;
	uint chunk = ack.receive_buffer_size < self.config.send_buffer_size ? ack.receive_buffer_size : self.config.send_buffer_size;
	self.writer.max_chunk_size = chunk;
	self.writer.max_message_size = ack.max_message_size;
	self.writer.max_chunk_count = ack.max_chunk_count;
	self.queue_open(false, now)!;
	self.state = State.OPN_SENT;
	self.handshake_deadline = now.mono_ms + self.config.handshake_timeout_ms;
}

// Response to an Issue or a Renew request.
fn void? Machine.on_open_response(&self, Message* m, Now now, bool renew)
{
	String wanted = self.security == null ? POLICY_NONE : self.security.policy_uri();
	if (m.policy_uri != wanted) return BAD_HANDSHAKE~;
	if (renew)
	{
		bool known = false;
		for (sz i = 0; i < self.renew_id_count; i++)
		{
			if (self.renew_ids[i] == m.request_id) known = true;
		}
		if (!known) return REQUEST_ID_UNKNOWN~;
	}
	else if (m.request_id != self.open_request_id)
	{
		return BAD_RESPONSE~;
	}
	uint channel;
	uint token;
	uint revised;
	@pool()
	{
		Decoder d = decoder(m.body, tmem, self.config.limits);
		NodeId tid = d.get_nodeid()!;
		if (tid.kind != NodeIdKind.NUMERIC || tid.ns != 0) return BAD_RESPONSE~;
		if (tid.num == SERVICE_FAULT_ENCODING_ID)
		{
			ResponseHeader fh = read_response_header(&d)!;
			self.last_status = fh.service_result;
			return SERVICE_FAULT~;
		}
		if (tid.num != OPEN_SECURE_CHANNEL_RESPONSE_ENCODING_ID) return BAD_RESPONSE~;
		ResponseHeader h = read_response_header(&d)!;
		if (h.request_handle != self.open_handle && !renew) return BAD_RESPONSE~;
		if (!status_is_good(h.service_result))
		{
			self.last_status = h.service_result;
			return SERVICE_FAULT~;
		}
		(void)d.get_u32()!;                          // ServerProtocolVersion
		channel = d.get_u32()!;
		token = d.get_u32()!;
		(void)d.get_u64()!;                          // CreatedAt: the local clock decides the schedule
		revised = d.get_u32()!;
		(void)d.get_bytestring()!;                   // ServerNonce
		if (d.remaining() != 0) return BAD_RESPONSE~;
	};
	if (channel == 0) return BAD_HANDSHAKE~;
	if (m.channel_id != channel) return CHANNEL_ID_MISMATCH~;
	if (renew)
	{
		if (channel != self.channel_id) return CHANNEL_ID_MISMATCH~;
		self.old_token_id = self.token_id;
		self.have_old_token = true;
		self.old_token_expires_ms = self.token_issued_ms + effective_lifetime(self.lifetime_ms);
		self.renew_pending = false;                  // the ids stay known: a slow answer to an earlier try is dropped quietly
	}
	self.channel_id = channel;
	self.token_id = token;
	self.lifetime_ms = effective_lifetime(revised);
	self.token_issued_ms = now.mono_ms;
	self.schedule_renewal();
	if (renew)
	{
		self.push_kind(EventKind.CHANNEL_RENEWED);
	}
	else
	{
		self.handshake_active = false;
		self.state = State.CHANNEL_OPEN;
		self.push_kind(EventKind.CHANNEL_OPEN);
	}
}

// ---------- ingress ----------
fn bool Machine.channel_up(&self)
{
	switch (self.state)
	{
		case CHANNEL_OPEN:
		case SESSION_CREATING:
		case SESSION_CREATED:
		case ACTIVATING:
		case ACTIVE:
		case CLOSING: return true;
		default: return false;
	}
}

fn void? Machine.feed(&self, char[] data, Now now)
{
	if (self.state == State.IDLE || self.state == State.CLOSED || self.state == State.FAILED) return BAD_STATE~;
	if (catch err = self.feed_frames(data, now))
	{
		self.fail(err, now);
		return err~;
	}
}

fn void? Machine.feed_frames(&self, char[] data, Now now)
{
	self.reader.feed(data)!;
	Message m;
	while (self.reader.next(&m)!)
	{
		if (self.state == State.CLOSING && !self.closing_session) continue;      // nothing is expected after our CLO
		self.on_message(&m, now)!;
	}
}

fn void? Machine.on_message(&self, Message* m, Now now)
{
	if (m.type == MsgType.ERR)
	{
		Decoder d = decoder(m.body, self.allocator);         // only the status is read, nothing is allocated
		if (try status = d.get_u32()) self.last_status = (StatusCode)status;
		return PEER_ERROR~;                                  // also for a body too short to carry a status
	}
	if (self.state == State.HEL_SENT)
	{
		if (m.type != MsgType.ACK) return BAD_HANDSHAKE~;
		return self.on_ack(m, now);
	}
	if (self.state == State.OPN_SENT)
	{
		if (m.type != MsgType.OPN) return BAD_HANDSHAKE~;
		return self.on_open_response(m, now, false);
	}
	if (self.state == State.CLOSING && m.type != MsgType.MSG) return;
	switch (m.type)
	{
		case MSG:
			if (m.aborted) return self.on_abort(m, now);
			return self.on_service(m, now);
		case OPN:
			if (!self.renew_pending)
			{
				// a slow server may answer the first try and the retry: the second answer is harmless
				if (self.is_renew_id(m.request_id)) return;
				return BAD_RESPONSE~;
			}
			return self.on_open_response(m, now, true);
		case CLO: return CHANNEL_CLOSED~;
		default: return BAD_HANDSHAKE~;
	}
}

fn void? Machine.check_token(&self, Message* m, Now now)
{
	if (m.channel_id != self.channel_id) return CHANNEL_ID_MISMATCH~;
	if (m.token_id == self.token_id)
	{
		self.have_old_token = false;            // the first chunk under the new token ends the old token's window
		return;
	}
	if (self.have_old_token && m.token_id == self.old_token_id && now.mono_ms < self.old_token_expires_ms) return;
	return TOKEN_UNKNOWN~;
}

fn sz Machine.find_pending(&self, uint request_id)
{
	for (sz i = 0; i < self.pending_count; i++)
	{
		if (self.pending[i].request_id == request_id) return i;
	}
	return self.pending_count;
}

fn void Machine.remove_pending(&self, sz idx)
{
	self.pending_count--;
	if (idx != self.pending_count) self.pending[idx] = self.pending[self.pending_count];
}

fn void Machine.remember_late(&self, uint id)
{
	if (self.late_count == MAX_REMEMBERED_IDS)
	{
		for (sz i = 1; i < MAX_REMEMBERED_IDS; i++) self.late_ids[i - 1] = self.late_ids[i];
		self.late_count--;
	}
	self.late_ids[self.late_count] = id;
	self.late_count++;
}

fn bool Machine.is_late(&self, uint id)
{
	for (sz i = 0; i < self.late_count; i++)
	{
		if (self.late_ids[i] == id) return true;
	}
	return false;
}

// Completes the request at `idx` with a failure status (no service body).
fn void Machine.complete_with_status(&self, sz idx, StatusCode status, bool local_timeout)
{
	PendingRequest p = self.pending[idx];
	self.remove_pending(idx);
	if (is_internal(p.kind)) return;                 // session handling and keep-alive have no caller to tell
	Event e = { .kind = EventKind.RESPONSE };
	e.response.kind = ResponseKind.SERVICE_FAULT;
	e.response.handle = p.handle;
	e.response.header.service_result = status;
	e.response.header.request_handle = p.handle;
	e.response.local_timeout = local_timeout;
	self.push_event(e);
}

fn bool Machine.is_renew_id(&self, uint id)
{
	for (sz i = 0; i < self.renew_id_count; i++)
	{
		if (self.renew_ids[i] == id) return true;
	}
	return false;
}

fn void? Machine.on_abort(&self, Message* m, Now now)
{
	self.check_token(m, now)!;
	sz idx = self.find_pending(m.request_id);
	if (idx == self.pending_count) return;           // an abort for a request we no longer wait for
	self.last_status = m.abort_status;
	if (is_internal(self.pending[idx].kind) && self.pending[idx].kind != PendingKind.CLOSE_SESSION) return SERVICE_FAULT~;
	self.complete_with_status(idx, m.abort_status, false);
	if (self.closing_session && self.pending_count == 0) self.begin_channel_close(now)!;
}

// ---------- failure and close ----------
fn void Machine.complete_all_pending(&self)
{
	while (self.pending_count > 0) self.complete_with_status(self.pending_count - 1, STATUS_BAD_CONNECTION_CLOSED, false);
}

fn void Machine.fail(&self, fault f, Now now)
{
	if (self.state == State.FAILED || self.state == State.CLOSED) return;
	self.complete_all_pending();
	self.state = State.FAILED;
	self.failure = f;
	self.handshake_active = false;
	self.renew_pending = false;
	self.push_kind(EventKind.FAILED);
}

// The adapter saw EOF: mid-frame -> TRANSPORT_TRUNCATED, between frames -> CLOSED; nothing happens after an orderly close.
fn void Machine.transport_closed(&self, Now now)
{
	if (self.state == State.CLOSED || self.state == State.FAILED) return;
	if (self.state == State.CLOSING)
	{
		self.finish_close();
		return;
	}
	if (self.state == State.IDLE)
	{
		self.state = State.CLOSED;
		return;
	}
	self.fail(self.reader.mid_frame() ? TRANSPORT_TRUNCATED : CLOSED, now);
}

fn void Machine.finish_close(&self)
{
	self.complete_all_pending();
	self.state = State.CLOSED;
	self.handshake_active = false;
	self.renew_pending = false;
	self.push_kind(EventKind.CLOSED);
}

// Queues the CloseSecureChannel chunk; the state becomes CLOSED after the output was consumed. A second call, or a call
// on a failed or closed machine, does nothing.
fn void? Machine.close(&self, Now now)
{
	switch (self.state)
	{
		case CLOSING:
		case CLOSED:
		case FAILED: return;
		case IDLE:
			self.state = State.CLOSED;
			return;
		case HEL_SENT:
		case OPN_SENT:
			self.finish_close();
			return;
		default:
	}
	if (self.have_session && (self.state == State.SESSION_CREATED || self.state == State.ACTIVATING || self.state == State.ACTIVE))
	{
		self.complete_all_pending();
		self.queue_close_session(now)!;
		self.state = State.CLOSING;
		self.closing_session = true;
		self.renew_pending = false;
		return;
	}
	self.begin_channel_close(now)!;
}

// Queues the CloseSecureChannel chunk (no answer expected) and enters CLOSING.
fn void? Machine.begin_channel_close(&self, Now now)
{
	uint rid = self.alloc_request_id();
	uint handle = self.alloc_handle();
	ByteBuf b;
	b.init(self.allocator, 64);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, CLOSE_SECURE_CHANNEL_REQUEST_ENCODING_ID))!;
	e.put_close_secure_channel_request({ .request_header = self.request_header(now, handle, 0) })!;
	self.writer.write_message(&self.outbox, MsgType.CLO, self.channel_id, self.token_id, rid, b.bytes())!;
	self.state = State.CLOSING;
	self.closing_session = false;
	self.renew_pending = false;
	if (self.out_pos >= self.outbox.len) self.finish_close();
}

// ---------- output ----------
// Bytes to send: a view into the outbox; call consume_output(n) after the transport accepted n bytes.
fn char[] Machine.pending_output(&self) => self.outbox.bytes()[self.out_pos..];

fn void Machine.consume_output(&self, sz n)
{
	sz left = self.outbox.len - self.out_pos;
	self.out_pos += n > left ? left : n;
	if (self.out_pos >= self.outbox.len)
	{
		self.outbox.clear();
		self.out_pos = 0;
		if (self.state == State.CLOSING && !self.closing_session) self.finish_close();
	}
}

// ---------- time ----------
// Next deadline in mono_ms: handshake, channel renewal (75% of the lifetime, retries), request timeouts.
// Returns false when nothing is scheduled (not an error).
fn bool Machine.next_deadline(&self, ulong* out)
{
	if (self.state == State.IDLE || self.state == State.CLOSED || self.state == State.FAILED) return false;
	bool have = false;
	ulong best = 0;
	if (self.handshake_active) { best = self.handshake_deadline; have = true; }
	if (self.channel_up() && self.state != State.CLOSING)
	{
		ulong t = self.renew_pending ? self.renew_retry_ms : self.next_renew_ms;
		if (!have || t < best) { best = t; have = true; }
		if (self.renew_pending)
		{
			ulong expiry = self.token_issued_ms + self.lifetime_ms;
			if (expiry < best) best = expiry;
		}
	}
	if (self.state == State.ACTIVE && self.have_session && !self.keepalive_pending)
	{
		ulong t = self.last_activity_ms + self.keepalive_interval();
		if (!have || t < best) { best = t; have = true; }
	}
	for (sz i = 0; i < self.pending_count; i++)
	{
		if (!have || self.pending[i].deadline < best) { best = self.pending[i].deadline; have = true; }
	}
	*out = best;
	return have;
}

fn void? Machine.handle_timeout(&self, Now now)
{
	if (self.state == State.IDLE || self.state == State.CLOSED || self.state == State.FAILED) return;
	if (catch err = self.run_timers(now))
	{
		self.fail(err, now);
		return err~;
	}
}

fn void? Machine.run_timers(&self, Now now)
{
	if (self.handshake_active && now.mono_ms >= self.handshake_deadline) return TIMEOUT~;
	if (self.channel_up() && self.state != State.CLOSING)
	{
		if (self.renew_pending)
		{
			if (now.mono_ms >= self.token_issued_ms + self.lifetime_ms) return TIMEOUT~;    // the old token ran out
			if (now.mono_ms >= self.renew_retry_ms)
			{
				self.push_kind(EventKind.CHANNEL_RENEW_FAILED);
				self.queue_open(true, now)!;
				self.renew_retry_ms = now.mono_ms + self.config.request_timeout_ms;
			}
		}
		else if (now.mono_ms >= self.next_renew_ms)
		{
			if (now.mono_ms >= self.token_issued_ms + self.lifetime_ms) return TIMEOUT~;
			self.renew_id_count = 0;                 // a new renewal starts: forget the ids of the last one
			self.queue_open(true, now)!;
			self.renew_pending = true;
			self.renew_retry_ms = now.mono_ms + self.config.request_timeout_ms;
		}
	}
	sz i = 0;
	while (i < self.pending_count)
	{
		if (self.pending[i].deadline <= now.mono_ms)
		{
			PendingKind kind = self.pending[i].kind;
			if (is_internal(kind) && kind != PendingKind.CLOSE_SESSION) return TIMEOUT~;     // session setup and keep-alive must answer
			self.remember_late(self.pending[i].request_id);
			self.complete_with_status(i, STATUS_BAD_TIMEOUT, true);
			if (kind == PendingKind.CLOSE_SESSION) self.begin_channel_close(now)!;          // no answer: close the channel anyway
		}
		else
		{
			i++;
		}
	}
	if (self.state == State.ACTIVE && self.have_session && !self.keepalive_pending && now.mono_ms >= self.last_activity_ms + self.keepalive_interval())
	{
		self.queue_keepalive(now)!;
	}
}

// ---------- requests ----------
// The smaller of the peer's MaxMessageSize (ACK) and the session's MaxRequestMessageSize, ignoring zeros; 0 = no limit.
fn sz Machine.request_size_limit(&self)
{
	sz a = self.writer.max_message_size;
	sz b = self.session_max_request;
	if (a == 0) return b;
	if (b == 0) return a;
	return a < b ? a : b;
}

// Queues one encoded request (type id and request structure). Nothing is queued and nothing changes when a check fails.
// The size limit is checked against the encoded request itself (type id and structure), not against the chunk and security
// headers added per chunk: a request of exactly the limit passes here and may still be refused by a strict server. The chunk
// writer uses the same convention.
fn uint? Machine.queue_encoded(&self, Allocator alloc, Now now, uint handle, PendingKind kind, uint expected_id, sz count, char[] message_body)
{
	bool internal = is_internal(kind);
	if (!internal && self.pending_count >= self.config.limits.max_outstanding_requests) return TOO_MANY_PENDING~;
	sz limit = self.request_size_limit();
	if (limit != 0 && message_body.len > limit) return MESSAGE_TOO_LARGE~;
	if (self.pending_count == self.pending.len)
	{
		sz cap = self.pending.len == 0 ? 8 : self.pending.len * 2;
		PendingRequest[] fresh = alloc::alloc_array_try(self.allocator, PendingRequest, cap)!;
		for (sz i = 0; i < self.pending_count; i++) fresh[i] = self.pending[i];
		if (self.pending.ptr != null) alloc::free(self.allocator, self.pending.ptr);
		self.pending = fresh;
	}
	uint rid = self.alloc_request_id();
	self.writer.write_message(&self.outbox, MsgType.MSG, self.channel_id, self.token_id, rid, message_body)!;
	self.pending[self.pending_count] = { rid, handle, now.mono_ms + self.config.request_timeout_ms, alloc, kind, expected_id, count };
	self.pending_count++;
	self.last_activity_ms = now.mono_ms;
	return handle;
}

// Queues one service request whose body (everything after the RequestHeader) the caller encoded. The answer comes back
// as a RAW response. Returns the handle.
fn uint? Machine.send_raw(&self, Allocator alloc, Now now, NodeId type_id, char[] body)
{
	if (self.state != State.CHANNEL_OPEN && self.state != State.ACTIVE) return BAD_STATE~;
	uint handle = self.alloc_handle();
	ByteBuf b;
	b.init(self.allocator, 128 + body.len);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(type_id)!;
	e.put_request_header(self.request_header(now, handle, self.config.request_timeout_ms))!;
	e.put_raw(body)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.RAW, 0, 0, b.bytes());
}
