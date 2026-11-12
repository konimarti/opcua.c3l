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
	foreach (n : nodes)
	{
		if (!index_range_valid(n.index_range)) return BAD_ENCODING~;
	}
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
	foreach (n : nodes)
	{
		if (!index_range_valid(n.index_range)) return BAD_ENCODING~;
	}
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

// ---------- index range ----------
// An IndexRange is `N`, `N:M` with N < M, or several of them separated by commas (one per dimension). Null is valid (no
// range); an empty string is treated like null. Everything else (signs, blanks, `5:5`, `7:3`, `1:`) is invalid.
fn bool index_range_valid(String r)
{
	if (r.ptr == null || r.len == 0) return true;
	sz i = 0;
	while (true)
	{
		ulong first;
		if (!read_index(r, &i, &first)) return false;
		if (i < r.len && r[i] == ':')
		{
			i++;
			ulong second;
			if (!read_index(r, &i, &second)) return false;
			if (first >= second) return false;
		}
		if (i == r.len) return true;
		if (r[i] != ',') return false;
		i++;
	}
}

fn bool read_index(String r, sz* at, ulong* value) @private
{
	sz i = *at;
	ulong v = 0;
	sz digits = 0;
	while (i < r.len && r[i] >= '0' && r[i] <= '9')
	{
		v = v * 10 + (ulong)(r[i] - '0');
		if (v > 0xFFFFFFFE) return false;
		i++;
		digits++;
	}
	if (digits == 0) return false;
	*at = i;
	*value = v;
	return true;
}

// ---------- discovery (CHANNEL_OPEN or later, no session needed, null AuthenticationToken) ----------
fn bool Machine.can_discover(&self)
{
	switch (self.state)
	{
		case CHANNEL_OPEN:
		case SESSION_CREATING:
		case SESSION_CREATED:
		case ACTIVATING:
		case ACTIVE: return true;
		default: return false;
	}
}

fn RequestHeader Machine.discovery_header(&self, Now now, uint handle)
{
	RequestHeader h = self.request_header(now, handle, self.config.request_timeout_ms);
	h.authentication_token = {};
	return h;
}

// `endpoint_url` is the URL the connection was made with. The machine never reconnects to a host named in the answer.
fn uint? Machine.send_get_endpoints(&self, Allocator alloc, Now now, String endpoint_url)
{
	if (!self.can_discover()) return BAD_STATE~;
	uint handle = self.alloc_handle();
	GetEndpointsRequest req = { .request_header = self.discovery_header(now, handle), .endpoint_url = endpoint_url };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, GET_ENDPOINTS_REQUEST_ENCODING_ID))!;
	e.put_get_endpoints_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.GET_ENDPOINTS, GET_ENDPOINTS_RESPONSE_ENCODING_ID, 0, b.bytes());
}

fn uint? Machine.send_find_servers(&self, Allocator alloc, Now now, String endpoint_url, String[] server_uris)
{
	if (!self.can_discover()) return BAD_STATE~;
	uint handle = self.alloc_handle();
	FindServersRequest req = { .request_header = self.discovery_header(now, handle), .endpoint_url = endpoint_url, .server_uris = server_uris };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, FIND_SERVERS_REQUEST_ENCODING_ID))!;
	e.put_find_servers_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.FIND_SERVERS, FIND_SERVERS_RESPONSE_ENCODING_ID, 0, b.bytes());
}

// A server without this service answers Bad_ServiceUnsupported or Bad_NotImplemented: that is a normal Response.
fn uint? Machine.send_find_servers_on_network(&self, Allocator alloc, Now now, uint starting_record_id, uint max_records)
{
	if (!self.can_discover()) return BAD_STATE~;
	uint handle = self.alloc_handle();
	FindServersOnNetworkRequest req = { .request_header = self.discovery_header(now, handle), .starting_record_id = starting_record_id, .max_records_to_return = max_records };
	ByteBuf b;
	b.init(self.allocator, 128);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, FIND_SERVERS_ON_NETWORK_REQUEST_ENCODING_ID))!;
	e.put_find_servers_on_network_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.FIND_SERVERS_ON_NETWORK, FIND_SERVERS_ON_NETWORK_RESPONSE_ENCODING_ID, 0, b.bytes());
}

// ---------- browse and translate (active session) ----------
fn uint? Machine.send_browse(&self, Allocator alloc, Now now, BrowseDescription[] nodes, uint max_refs_per_node)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (nodes.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	BrowseRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .requested_max_references_per_node = max_refs_per_node, .nodes_to_browse = nodes };
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, BROWSE_REQUEST_ENCODING_ID))!;
	e.put_browse_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.BROWSE, BROWSE_RESPONSE_ENCODING_ID, nodes.len, b.bytes());
}

// With `release` the server frees the continuation points and answers with empty results (one per point).
fn uint? Machine.send_browse_next(&self, Allocator alloc, Now now, char[][] continuation_points, bool release)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (continuation_points.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	BrowseNextRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .release_continuation_points = release, .continuation_points = continuation_points };
	ByteBuf b;
	b.init(self.allocator, 128);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, BROWSE_NEXT_REQUEST_ENCODING_ID))!;
	e.put_browse_next_request(req)!;
	return self.queue_encoded(alloc, now, handle, PendingKind.BROWSE_NEXT, BROWSE_NEXT_RESPONSE_ENCODING_ID, continuation_points.len, b.bytes());
}

// One BrowsePath per entry of `paths`, all starting at `start`.
fn uint? Machine.send_translate(&self, Allocator alloc, Now now, NodeId start, RelativePathElement[][] paths)
{
	if (self.state != State.ACTIVE) return BAD_STATE~;
	if (paths.len == 0) return EMPTY_REQUEST~;
	uint handle = self.alloc_handle();
	@pool()
	{
		BrowsePath[] list = alloc::alloc_array(tmem, BrowsePath, paths.len);
		foreach (i, p : paths) list[i] = { .starting_node = start, .relative_path = { .elements = p } };
		TranslateBrowsePathsToNodeIdsRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .browse_paths = list };
		ByteBuf b;
		b.init(self.allocator, 256);
		defer b.free();
		Encoder e = encoder(&b);
		e.put_nodeid(nodeid_num(0, TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_REQUEST_ENCODING_ID))!;
		e.put_translate_browse_paths_to_node_ids_request(req)!;
		return self.queue_encoded(alloc, now, handle, PendingKind.TRANSLATE, TRANSLATE_BROWSE_PATHS_TO_NODE_IDS_RESPONSE_ENCODING_ID, paths.len, b.bytes());
	};
}
