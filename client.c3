module opcua;
import std::io;
import std::collections::list;
import std::time;
import std::math::random;

// Blocking adapter: Machine + Transport. Not thread-safe (one caller at a time). There are NO hidden threads: timers
// (channel renewal, session keep-alive) only run while the caller is inside a Client call, so an idle program must call
// `service()` at least every `next_deadline()`.
struct Client
{
	Allocator allocator;
	Machine machine;
	Transport transport;
	Duration io_timeout;
	char[] io_buf;
	String endpoint_url;      // the URL passed to client_connect (a copy)
	StatusCode last_status;   // status of the last SERVICE_FAULT / BAD_STATUS / PEER_ERROR (copy of machine.last_status)
	uint renewals;            // CHANNEL_RENEWED events seen
	uint renew_failures;      // CHANNEL_RENEW_FAILED events seen
	bool verbose;             // print the redacted trace of every chunk to stderr
	FrameTracer trace_out;
	FrameTracer trace_in;
	bool closed;
}

fn Duration default_io_timeout() => time::sec(10);

fn bool all_zero(char[] b)
{
	foreach (x : b)
	{
		if (x != 0) return false;
	}
	return true;
}

// connect: HEL/ACK, OPN over an already connected transport. After it returns the channel is open. The client takes ownership
// of the transport on success and on failure: Client.free (or a failed connect) closes it. The client nonce comes from the
// OS entropy unless the config brings its own.
fn Client*? client_connect(Allocator allocator, Transport transport, String endpoint_url, Config config = default_config(), bool verbose = false)
{
	if (all_zero(config.nonce_entropy[:32]) && config.nonce_seed == 0) config.nonce_entropy = random::entropy();
	Client* c = alloc::new_try(allocator, Client)!;
	*c = {};
	c.allocator = allocator;
	c.transport = transport;
	c.io_timeout = default_io_timeout();
	c.verbose = verbose;
	c.machine.init(allocator, config);                   // from here on c.free() is safe on every path
	c.trace_out.init(allocator, config.receive_buffer_size);
	c.trace_in.init(allocator, config.receive_buffer_size);
	char[]? buf = alloc::alloc_array_try(allocator, char, 16384);
	if (catch err = buf)
	{
		c.free();
		return err~;
	}
	c.io_buf = buf;
	char[]? url = alloc::alloc_array_try(allocator, char, endpoint_url.len + 1);
	if (catch err = url)
	{
		c.free();
		return err~;
	}
	if (endpoint_url.len > 0) mem::copy(url.ptr, endpoint_url.ptr, endpoint_url.len);
	c.endpoint_url = (String)url[:endpoint_url.len];
	if (catch err = c.machine.connect(endpoint_url, clock_now()))
	{
		c.free();
		return err~;
	}
	if (catch err = c.wait_for(EventKind.CHANNEL_OPEN))
	{
		c.free();
		return err~;
	}
	return c;
}

fn void? Client.open_session(&self, Identity identity = identity_anonymous())
{
	self.machine.handle_timeout(clock_now())!;
	self.machine.open_session(identity, clock_now())!;
	self.wait_for(EventKind.SESSION_ACTIVE)!;
}

// Orderly close: CloseSession (when a session exists), CloseSecureChannel, then the transport. Calling it twice is fine.
fn void? Client.close(&self)
{
	if (self.closed) return;
	self.closed = true;
	fault failure = NOT_CONNECTED;
	bool queued = true;
	if (catch err = self.machine.close(clock_now()))
	{
		failure = err;
		queued = false;
	}
	if (queued)
	{
		for (int i = 0; i < 1000 && self.machine.state != State.CLOSED && self.machine.state != State.FAILED; i++)
		{
			if (catch err = self.pump(self.io_timeout)) break;
		}
	}
	(void)self.transport.close();
	if (!queued) return failure~;
}

fn void Client.free(&self)
{
	if (!self.closed) (void)self.transport.close();
	self.closed = true;
	self.machine.free();
	self.trace_out.free();
	self.trace_in.free();
	if (self.io_buf.ptr != null) alloc::free(self.allocator, self.io_buf.ptr);
	if (self.endpoint_url.ptr != null) alloc::free(self.allocator, self.endpoint_url.ptr);
	Allocator a = self.allocator;
	alloc::free(a, self);
}

// ---------- the I/O loop ----------
fn void Client.trace_bytes(&self, FrameTracer* t, String direction, char[] data)
{
	ByteBuf text;
	text.init(self.allocator, 256);
	defer text.free();
	t.feed(data, &text);
	if (text.len > 0) io::eprintf("%s%s", direction, (String)text.bytes());
}

// Hands the machine's output to the transport.
fn void? Client.flush(&self)
{
	while (self.machine.pending_output().len > 0)
	{
		char[] out = self.machine.pending_output();
		if (self.verbose) self.trace_bytes(&self.trace_out, "> ", out);
		if (catch err = self.transport.write(out, self.io_timeout))
		{
			// The machine must know: a chunk that was sent in part cannot be repaired, and after CLOSED nothing more goes out.
			Now now = clock_now();
			if (err == TIMEOUT)
			{
				self.machine.fail(TIMEOUT, now);
			}
			else
			{
				self.machine.transport_closed(now);
			}
			self.mirror_status();
			if (self.machine.state == State.FAILED) return self.machine.failure~;
			return err~;
		}
		self.machine.consume_output(out.len);
	}
}

fn Duration ms_duration(ulong ms) => time::ms((long)ms);

// One step: send what is queued, wait for bytes (at most `wait`, and not beyond the next machine deadline), feed them, then
// run the timers. A read that times out is not an error here: the deadlines of the machine decide when something failed.
fn void? Client.pump(&self, Duration wait)
{
	self.flush()!;
	Now now = clock_now();
	ulong deadline;
	Duration w = wait;
	if (self.machine.next_deadline(&deadline))
	{
		Duration until = deadline > now.mono_ms ? ms_duration(deadline - now.mono_ms) : time::DURATION_ZERO;
		if (until.to_ms() < w.to_ms()) w = until;
	}
	usz? n = self.transport.read(self.io_buf, w);
	if (catch err = n)
	{
		if (err == CLOSED)
		{
			self.machine.transport_closed(clock_now());
			self.mirror_status();
			if (self.machine.state == State.CLOSED) return;
			return self.machine.failure~;
		}
		if (err != TIMEOUT) return err~;
	}
	else
	{
		if (self.verbose) self.trace_bytes(&self.trace_in, "< ", self.io_buf[:n]);
		if (catch ferr = self.machine.feed(self.io_buf[:n], clock_now()))
		{
			self.mirror_status();
			return ferr~;
		}
	}
	if (catch terr = self.machine.handle_timeout(clock_now()))
	{
		self.mirror_status();
		return terr~;
	}
	self.mirror_status();
	self.flush()!;
}

fn void Client.mirror_status(&self) => self.last_status = self.machine.last_status;

// Every Client call starts here: an overdue renewal goes out before the request.
fn void? Client.begin_call(&self)
{
	if (self.closed) return NOT_CONNECTED~;
	if (self.machine.state == State.FAILED) return self.machine.failure~;
	if (self.machine.state == State.CLOSED) return NOT_CONNECTED~;
	if (catch err = self.machine.handle_timeout(clock_now()))
	{
		self.mirror_status();
		return err~;
	}
	self.flush()!;
}

// Waits for an event of `kind`; other events are counted or dropped. FAILED returns the machine's fault.
fn void? Client.wait_for(&self, EventKind kind)
{
	while (true)
	{
		Event e;
		while (self.machine.poll_event(&e))
		{
			if (e.kind == kind) return;
			self.note(&e);
			if (e.kind == EventKind.FAILED)
			{
				self.mirror_status();
				return self.machine.failure~;
			}
			if (e.kind == EventKind.CLOSED) return NOT_CONNECTED~;
		}
		self.pump(self.io_timeout)!;
	}
}

fn void Client.note(&self, Event* e)
{
	if (e.kind == EventKind.CHANNEL_RENEWED) self.renewals++;
	if (e.kind == EventKind.CHANNEL_RENEW_FAILED) self.renew_failures++;
}

// Waits for the response of `handle`. A local timeout is the fault TIMEOUT (it comes from the machine's request deadline);
// a ServiceFault or a Bad ServiceResult is the fault SERVICE_FAULT with the status in last_status.
fn Response? Client.wait_response(&self, uint handle)
{
	while (true)
	{
		Event e;
		while (self.machine.poll_event(&e))
		{
			self.note(&e);
			if (e.kind == EventKind.FAILED)
			{
				self.mirror_status();
				return self.machine.failure~;
			}
			if (e.kind == EventKind.CLOSED) return NOT_CONNECTED~;
			if (e.kind != EventKind.RESPONSE || e.response.handle != handle) continue;
			Response r = e.response;
			if (r.local_timeout) return TIMEOUT~;
			if (r.kind == ResponseKind.SERVICE_FAULT || status_is_bad(r.header.service_result))
			{
				self.last_status = r.header.service_result;
				return SERVICE_FAULT~;
			}
			return r;
		}
		self.pump(self.io_timeout)!;
	}
}

// Runs timers and reads incoming bytes for at most `max_wait`, without sending a request (renewal, keep-alive, late replies).
fn void? Client.service(&self, Duration max_wait)
{
	self.begin_call()!;
	self.pump(max_wait)!;
	Event e;
	while (self.machine.poll_event(&e))
	{
		self.note(&e);
		if (e.kind == EventKind.FAILED)
		{
			self.mirror_status();
			return self.machine.failure~;
		}
	}
}

// Time until the next timer needs service(); false when none is scheduled.
fn bool Client.next_deadline(&self, Duration* out)
{
	ulong deadline;
	if (!self.machine.next_deadline(&deadline)) return false;
	ulong now = clock_now().mono_ms;
	*out = deadline > now ? ms_duration(deadline - now) : time::DURATION_ZERO;
	return true;
}

// ---------- services ----------
// All results are allocated in `alloc` (usually an arena) and owned by the caller. Per-node StatusCodes are data inside the
// result structs; only a ServiceFault or a Bad ServiceResult is the fault SERVICE_FAULT (status in Client.last_status).
fn EndpointDescription[]? Client.get_endpoints(&self, Allocator alloc)
{
	self.begin_call()!;
	uint h = self.machine.send_get_endpoints(alloc, clock_now(), self.endpoint_url)!;
	return self.wait_response(h)!.endpoints;
}

fn ApplicationDescription[]? Client.find_servers(&self, Allocator alloc)
{
	self.begin_call()!;
	uint h = self.machine.send_find_servers(alloc, clock_now(), self.endpoint_url, {})!;
	return self.wait_response(h)!.servers;
}

fn ServerOnNetwork[]? Client.find_servers_on_network(&self, Allocator alloc)
{
	self.begin_call()!;
	uint h = self.machine.send_find_servers_on_network(alloc, clock_now(), 0, 0)!;
	return self.wait_response(h)!.servers_on_network;
}

// Browse one node with automatic BrowseNext until the continuation point is empty; the merged references and the FINAL
// status are returned (a Bad status is not an empty list). If it stops early on a fault, the continuation point still held is
// released best-effort (BrowseNext with release = true).
fn BrowseResult? Client.browse(&self, Allocator alloc, NodeId node, BrowseDirection dir = BrowseDirection.FORWARD, uint max_refs = 0)
{
	self.begin_call()!;
	BrowseDescription[1] nodes = { { .node_id = node, .browse_direction = dir, .include_subtypes = true, .result_mask = 63 } };
	uint h = self.machine.send_browse(alloc, clock_now(), &nodes, max_refs)!;
	Response first = self.wait_response(h)!;
	BrowseResult result = first.browse_results[0];
	List{ReferenceDescription} merged;
	merged.init(self.allocator);
	defer merged.free();
	foreach (r : result.references) merged.push(r);
	char[] point = result.continuation_point;
	StatusCode status = result.status_code;
	uint pages = 0;
	while (point.len > 0 && !status_is_bad(status))
	{
		pages++;
		if (pages > self.machine.config.limits.max_browse_pages || merged.len() > self.machine.config.limits.max_browse_references)
		{
			self.release_point(alloc, point);                 // a server that never stops must not make the client grow without bound
			return TOO_MANY_PAGES~;
		}
		char[][1] points = { point };
		Response? next = self.browse_next(alloc, &points, false);
		if (catch err = next)
		{
			self.release_point(alloc, point);                 // best effort: the point must not stay on the server
			return err~;
		}
		BrowseResult part = next.browse_results[0];
		foreach (r : part.references) merged.push(r);
		status = part.status_code;
		point = part.continuation_point;
	}
	if (point.len > 0) self.release_point(alloc, point);
	ReferenceDescription[] refs = alloc::alloc_array_try(alloc, ReferenceDescription, merged.len() == 0 ? 1 : merged.len())!;
	foreach (i, r : merged) refs[i] = r;
	return { .status_code = status, .references = refs[:merged.len()] };
}

fn Response? Client.browse_next(&self, Allocator alloc, char[][] points, bool release)
{
	uint h = self.machine.send_browse_next(alloc, clock_now(), points, release)!;
	return self.wait_response(h);
}

fn void Client.release_point(&self, Allocator alloc, char[] point)
{
	char[][1] points = { point };
	(void)self.browse_next(alloc, &points, true);
}

fn BrowsePathResult? Client.translate(&self, Allocator alloc, NodeId start, RelativePathElement[] path)
{
	self.begin_call()!;
	RelativePathElement[][1] paths = { path };
	uint h = self.machine.send_translate(alloc, clock_now(), start, &paths)!;
	return self.wait_response(h)!.paths[0];
}

fn DataValue? Client.read(&self, Allocator alloc, NodeId node, uint attribute = ATTRIBUTE_VALUE)
{
	ReadValueId[1] nodes = { { .node_id = node, .attribute_id = attribute } };
	DataValue[] values = self.read_many(alloc, &nodes)!;
	return values[0];
}

fn DataValue[]? Client.read_many(&self, Allocator alloc, ReadValueId[] nodes)
{
	self.begin_call()!;
	uint h = self.machine.send_read(alloc, clock_now(), nodes, 0.0)!;
	return self.wait_response(h)!.values;
}

// Fails with WRITE_NOT_ALLOWED unless Config.allow_write; returns the per-node StatusCode. No type coercion: the Variant is
// sent as given.
fn StatusCode? Client.write(&self, Allocator alloc, NodeId node, Variant value)
{
	self.begin_call()!;
	WriteValue[1] w = { write_value(node, value) };
	uint h = self.machine.send_write(alloc, clock_now(), &w)!;
	return self.wait_response(h)!.statuses[0];
}

// Fails with WRITE_NOT_ALLOWED unless Config.allow_write (a call can change state).
fn CallMethodResult? Client.call(&self, Allocator alloc, NodeId object, NodeId method, Variant[] args)
{
	self.begin_call()!;
	CallMethodRequest[1] calls = { { .object_id = object, .method_id = method, .input_arguments = args } };
	uint h = self.machine.send_call(alloc, clock_now(), &calls)!;
	return self.wait_response(h)!.calls[0];
}
