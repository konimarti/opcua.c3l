module opcua;

// Response path of the machine: a chunk-level RequestId finds the pending request, the RequestHandle in the header and the
// type id in the body must agree with it, and the body must be exactly the expected response.

const uint PUBLISH_RESPONSE_ENCODING_ID = 829;
const uint SERVER_STATE_NODE_ID = 2259;               // Server_ServerStatus_State: the keep-alive reads it

// Response type ids this library knows. A response with one of them and no request waiting for it is dropped quietly.
fn bool known_response_id(uint id)
{
	switch (id)
	{
		case SERVICE_FAULT_ENCODING_ID:
		case OPEN_SECURE_CHANNEL_RESPONSE_ENCODING_ID:
		case CREATE_SESSION_RESPONSE_ENCODING_ID:
		case ACTIVATE_SESSION_RESPONSE_ENCODING_ID:
		case CLOSE_SESSION_RESPONSE_ENCODING_ID:
		case GET_ENDPOINTS_RESPONSE_ENCODING_ID:
		case FIND_SERVERS_RESPONSE_ENCODING_ID:
		case FIND_SERVERS_ON_NETWORK_RESPONSE_ENCODING_ID:
		case BROWSE_RESPONSE_ENCODING_ID:
		case BROWSE_NEXT_RESPONSE_ENCODING_ID:
		case TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_RESPONSE_ENCODING_ID:
		case READ_RESPONSE_ENCODING_ID:
		case WRITE_RESPONSE_ENCODING_ID:
		case CALL_RESPONSE_ENCODING_ID:
		case PUBLISH_RESPONSE_ENCODING_ID: return true;
		default: return false;
	}
}

// BadSessionIdInvalid, BadSessionClosed, BadSessionNotActivated: the session is gone, a reconnect is needed.
fn bool is_session_lost(StatusCode s)
{
	uint code = (uint)s & 0xFFFF0000;
	return code == 0x80250000 || code == 0x80260000 || code == 0x80270000;
}

fn void? Machine.on_service(&self, Message* m, Now now)
{
	self.check_token(m, now)!;
	uint type_num = 0;
	sz after_tid = 0;
	@pool()
	{
		Decoder d = decoder(m.body, tmem, self.config.limits);
		NodeId tid = d.get_nodeid()!;
		after_tid = d.pos;
		if (tid.kind == NodeIdKind.NUMERIC && tid.ns == 0) type_num = tid.num;
	};
	sz idx = self.find_pending(m.request_id);
	if (idx == self.pending_count)
	{
		bool late = self.is_late(m.request_id);          // answer to a request that already timed out
		if (late || known_response_id(type_num))         // or a response nobody asked for (for example a Publish answer)
		{
			// The reply is dropped, but a lost session reported by a ServiceFault must not be missed.
			if (type_num == SERVICE_FAULT_ENCODING_ID) return self.check_fault_for_lost_session(m, after_tid);
			return;
		}
		return REQUEST_ID_UNKNOWN~;
	}
	self.last_activity_ms = now.mono_ms;
	return self.dispatch_response(idx, m, type_num, after_tid, now);
}

fn void? Machine.check_fault_for_lost_session(&self, Message* m, sz after_tid)
{
	@pool()
	{
		Decoder d = decoder(m.body[after_tid..], tmem, self.config.limits);
		ResponseHeader h = read_response_header(&d)!;
		if (is_session_lost(h.service_result))
		{
			self.last_status = h.service_result;
			return SESSION_LOST~;
		}
	};
}

fn void? Machine.dispatch_response(&self, sz idx, Message* m, uint type_num, sz after_tid, Now now)
{
	PendingRequest p = self.pending[idx];
	ResponseHeader h;
	sz header_end = 0;
	@pool()
	{
		Decoder d = decoder(m.body[after_tid..], tmem, self.config.limits);
		h = read_response_header(&d)!;
		header_end = after_tid + d.pos;
	};
	if (h.request_handle != p.handle) return BAD_RESPONSE~;
	bool is_fault = type_num == SERVICE_FAULT_ENCODING_ID;
	if (!is_fault && p.kind != PendingKind.RAW && type_num != p.expected_id) return BAD_RESPONSE~;
	if (is_fault && header_end != m.body.len) return BAD_RESPONSE~;
	if (p.kind == PendingKind.CLOSE_SESSION)
	{
		self.remove_pending(idx);                        // whatever the answer, the channel is closed next
		return self.begin_channel_close(now);
	}
	if (is_session_lost(h.service_result))
	{
		self.last_status = h.service_result;
		return SESSION_LOST~;
	}
	if (is_internal(p.kind) && (is_fault || status_is_bad(h.service_result)))
	{
		self.last_status = h.service_result;
		return SERVICE_FAULT~;
	}
	Event e = { .kind = EventKind.RESPONSE };
	e.response.handle = p.handle;
	e.response.header = h;
	if (is_fault)
	{
		self.last_status = h.service_result;
		e.response.kind = ResponseKind.SERVICE_FAULT;
		self.remove_pending(idx);
		self.push_event(e);
		return;
	}
	char[] rest = m.body[header_end..];
	switch (p.kind)
	{
		case RAW:
			e.response.kind = ResponseKind.RAW;
			char[]? copy = alloc::alloc_array_try(p.allocator, char, rest.len == 0 ? 1 : rest.len);
			if (catch copy)
			{
				self.complete_with_status(idx, STATUS_BAD_OUT_OF_MEMORY, false);    // only this request fails
				return;
			}
			if (rest.len > 0) mem::copy(copy.ptr, rest.ptr, rest.len);
			e.response.raw = copy[:rest.len];
		case READ:
			Decoder d = decoder(m.body[after_tid..], p.allocator, self.config.limits);
			ReadResponse r = d.get_read_response()!;
			if (d.remaining() != 0) return BAD_RESPONSE~;
			if (!status_is_bad(r.response_header.service_result) && r.results.len != p.count) return BAD_RESPONSE~;
			e.response.kind = ResponseKind.READ;
			e.response.header = r.response_header;
			e.response.values = r.results;
		case WRITE:
			Decoder d = decoder(m.body[after_tid..], p.allocator, self.config.limits);
			WriteResponse r = d.get_write_response()!;
			if (d.remaining() != 0) return BAD_RESPONSE~;
			if (!status_is_bad(r.response_header.service_result) && r.results.len != p.count) return BAD_RESPONSE~;
			e.response.kind = ResponseKind.WRITE;
			e.response.header = r.response_header;
			e.response.statuses = r.results;
		case CALL:
			Decoder d = decoder(m.body[after_tid..], p.allocator, self.config.limits);
			CallResponse r = d.get_call_response()!;
			if (d.remaining() != 0) return BAD_RESPONSE~;
			if (!status_is_bad(r.response_header.service_result) && r.results.len != p.count) return BAD_RESPONSE~;
			e.response.kind = ResponseKind.CALL;
			e.response.header = r.response_header;
			e.response.calls = r.results;
		case CREATE_SESSION: return self.on_create_session(idx, m, after_tid, now);
		case ACTIVATE_SESSION: return self.on_activate_session(idx, m, after_tid, now);
		case KEEPALIVE: return self.on_keepalive(idx, m, after_tid, now);
		default: return BAD_RESPONSE~;
	}
	self.remove_pending(idx);
	self.push_event(e);
}
