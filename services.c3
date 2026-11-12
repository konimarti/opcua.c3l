module opcua;

// Service requests on an active session. A request is checked before anything is queued: state, write gate, empty list,
// then size limits and the outstanding-request limit in queue_encoded. `alloc` receives the decoded response.

// A WriteValue for the Value attribute with a value-only DataValue (no status, no timestamps), the form servers accept.
fn WriteValue write_value(NodeId node, Variant value)
{
	return { .node_id = node, .attribute_id = ATTRIBUTE_VALUE, .value = { .value = value, .has_value = true } };
}

fn uint? Machine.send_read(&self, Allocator alloc, Now now, ReadValueId[] nodes, double max_age_ms, TimestampsToReturn ts = TimestampsToReturn.NEITHER)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (nodes.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	ReadRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .max_age = max_age_ms, .timestamps_to_return = ts, .nodes_to_read = nodes };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, READ_REQUEST_ENCODING_ID))!;
	e.put_read_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.READ, READ_RESPONSE_ENCODING_ID, nodes.len, b.bytes());
}

// Refused with WRITE_NOT_ALLOWED unless Config.allow_write is set (the same flag covers Call).
fn uint? Machine.send_write(&self, Allocator alloc, Now now, WriteValue[] nodes)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (!self.config.allow_write) return WRITE_NOT_ALLOWED~;
	if (nodes.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	WriteRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .nodes_to_write = nodes };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, WRITE_REQUEST_ENCODING_ID))!;
	e.put_write_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.WRITE, WRITE_RESPONSE_ENCODING_ID, nodes.len, b.bytes());
}

fn uint? Machine.send_call(&self, Allocator alloc, Now now, CallMethodRequest[] calls)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (!self.config.allow_write) return WRITE_NOT_ALLOWED~;
	if (calls.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	CallRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .methods_to_call = calls };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, CALL_REQUEST_ENCODING_ID))!;
	e.put_call_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.CALL, CALL_RESPONSE_ENCODING_ID, calls.len, b.bytes());
}
