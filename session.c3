module opcua;

// Session handling of the machine: CreateSession, ActivateSession, keep-alive and CloseSession (10000-4 5.6).

// The endpoint with the given security mode and policy from a GetEndpoints / CreateSession result, or null.
// The client never reconnects to the host in the result by itself.
fn EndpointDescription* find_endpoint(EndpointDescription[] endpoints, MessageSecurityMode mode, String policy_uri)
{
	foreach (&ep : endpoints)
	{
		if (ep.security_mode == mode && ep.security_policy_uri == policy_uri) return ep;
	}
	return null;
}

// The UserTokenPolicy of `type` that the chosen endpoint offers, or null when it offers none.
fn UserTokenPolicy* find_token_policy(EndpointDescription* endpoint, UserTokenType type)
{
	foreach (&p : endpoint.user_identity_tokens)
	{
		if (p.token_type == type) return p;
	}
	return null;
}

fn String? copy_string(Allocator a, String s)
{
	if (s.ptr == null) return s;
	char[] c = alloc::alloc_array_try(a, char, s.len == 0 ? 1 : s.len)!;
	if (s.len > 0) mem::copy(c.ptr, s.ptr, s.len);
	return (String)c[:s.len];
}

// splitmix64: the nonce comes from Config.nonce_seed, the core reads no entropy source.
fn ulong Machine.next_random(&self)
{
	self.nonce_state += 0x9E3779B97F4A7C15;
	ulong z = self.nonce_state;
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
	return z ^ (z >> 31);
}

// Starts a session (after CHANNEL_OPEN): CreateSession, then ActivateSession automatically. USERNAME is refused
// without Config.allow_cleartext_password; the policy the server offers is checked when its answer arrives.
fn void? Machine.open_session(&self, Identity identity, Now now)
{
	if (self.state != State.CHANNEL_OPEN) return BAD_STATE~;
	if (identity.type == UserTokenType.USER_NAME)
	{
		if (!self.config.allow_cleartext_password) return SECURITY_UNSUPPORTED~;
	}
	else if (identity.type != UserTokenType.ANONYMOUS)
	{
		return SECURITY_UNSUPPORTED~;
	}
	if (!self.arena_ready)
	{
		self.arena.init(self.allocator, 4096);
		self.arena_ready = true;
	}
	Allocator a = &self.arena;
	Identity keep = { identity.type, copy_string(a, identity.username)!, copy_string(a, identity.password)! };
	self.nonce_state = self.config.nonce_seed;
	char[32] nonce;
	for (sz i = 0; i < 32; i += 8)
	{
		ulong r = self.next_random();
		for (sz k = 0; k < 8; k++) nonce[i + k] = (char)(r >> (8 * k));
	}
	Config c = self.config;
	uint handle = self.alloc_handle();
	CreateSessionRequest req = {
		.request_header = self.request_header(now, handle, c.request_timeout_ms),
		.client_description = { .application_uri = c.application_uri, .product_uri = c.product_uri, .application_name = { .text = c.application_name }, .application_type = ApplicationType.CLIENT },
		.endpoint_url = self.endpoint_url,
		.session_name = c.session_name,
		.client_nonce = nonce[:32],
		.requested_session_timeout = c.session_timeout_ms > 0 ? c.session_timeout_ms : 1200000.0,
		.max_response_message_size = c.max_response_message_size,
	};
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, CREATE_SESSION_REQUEST_ENCODING_ID))!;
	e.put_create_session_request(req)!;
	self.queue_encoded(self.allocator, now, handle, PendingKind.CREATE_SESSION, CREATE_SESSION_RESPONSE_ENCODING_ID, 0, b.bytes())!;
	self.identity = keep;
	self.state = State.SESSION_CREATING;
}

fn void? Machine.on_create_session(&self, sz idx, Message* m, sz after_tid, Now now)
{
	Decoder d = decoder(m.body[after_tid..], &self.arena, self.config.limits);
	CreateSessionResponse r = d.get_create_session_response()!;
	if (d.remaining() != 0) return BAD_RESPONSE~;
	NodeId sid = r.session_id;
	if (sid.kind == NodeIdKind.NUMERIC && sid.ns == 0 && sid.num == 0) return BAD_RESPONSE~;
	NodeId token = r.authentication_token;
	if (token.kind == NodeIdKind.NUMERIC && token.ns == 0 && token.num == 0) return BAD_RESPONSE~;
	double t = r.revised_session_timeout;
	self.session_timeout_ms = (t > 0 && t < 1.0e12) ? t : DEFAULT_SESSION_TIMEOUT_MS;     // NaN, 0, negative and infinite
	self.session_max_request = r.max_request_message_size;
	self.auth_token = token;
	self.endpoints = r.server_endpoints;
	self.have_session = true;
	self.state = State.SESSION_CREATED;
	self.remove_pending(idx);
	self.queue_activate(now)!;
}

fn void? Machine.queue_activate(&self, Now now)
{
	EndpointDescription* ep = find_endpoint(self.endpoints, MessageSecurityMode.NONE, POLICY_NONE);
	if (ep == null) return BAD_STATE~;
	UserTokenPolicy* policy = find_token_policy(ep, self.identity.type);
	if (policy == null || is_null(policy.policy_id)) return BAD_STATE~;
	// A password under a policy that names a security policy would have to be encrypted: never sent in the clear.
	if (self.identity.type == UserTokenType.USER_NAME && policy.security_policy_uri.len != 0) return SECURITY_UNSUPPORTED~;
	ByteBuf tb;
	tb.init(self.allocator, 64);
	defer tb.free();
	Encoder te = encoder(&tb);
	ExtensionObject token = { .encoding = 1 };
	if (self.identity.type == UserTokenType.USER_NAME)
	{
		UserNameIdentityToken t = { .policy_id = policy.policy_id, .user_name = self.identity.username, .password = (char[])self.identity.password };
		te.put_user_name_identity_token(t)!;
		token.type_id = nodeid_num(0, USER_NAME_IDENTITY_TOKEN_ENCODING_ID);
	}
	else
	{
		AnonymousIdentityToken t = { .policy_id = policy.policy_id };
		te.put_anonymous_identity_token(t)!;
		token.type_id = nodeid_num(0, ANONYMOUS_IDENTITY_TOKEN_ENCODING_ID);
	}
	token.body = tb.bytes();
	uint handle = self.alloc_handle();
	ActivateSessionRequest req = {
		.request_header = self.request_header(now, handle, self.config.request_timeout_ms),
		.user_identity_token = token,
	};
	ByteBuf b;
	b.init(self.allocator, 256);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, ACTIVATE_SESSION_REQUEST_ENCODING_ID))!;
	e.put_activate_session_request(req)!;
	self.queue_encoded(self.allocator, now, handle, PendingKind.ACTIVATE_SESSION, ACTIVATE_SESSION_RESPONSE_ENCODING_ID, 0, b.bytes())!;
	self.state = State.ACTIVATING;
	// The password has been used: overwrite every copy (the token buffer, the request buffer, the copy of the identity).
	if (tb.len > 0) mem::clear(tb.data.ptr, tb.len);
	if (b.len > 0) mem::clear(b.data.ptr, b.len);
	if (self.identity.password.len > 0) mem::clear(self.identity.password.ptr, self.identity.password.len);
	self.identity.password = {};
}

fn void? Machine.on_activate_session(&self, sz idx, Message* m, sz after_tid, Now now)
{
	@pool()
	{
		Decoder d = decoder(m.body[after_tid..], tmem, self.config.limits);
		(void)d.get_activate_session_response()!;
		if (d.remaining() != 0) return BAD_RESPONSE~;
	};
	self.remove_pending(idx);
	self.state = State.ACTIVE;
	self.last_activity_ms = now.mono_ms;
	self.push_kind(EventKind.SESSION_ACTIVE);
}

fn ulong Machine.keepalive_interval(&self)
{
	ulong half = (ulong)(self.session_timeout_ms / 2);
	return half < 1 ? 1 : half;
}

// Idle for half of the session timeout: read the server state through the normal request table. Its answer is consumed
// internally, but a failure is not swallowed (see dispatch_response).
fn void? Machine.queue_keepalive(&self, Now now)
{
	uint handle = self.alloc_handle();
	ReadValueId[1] node = { { .node_id = nodeid_num(0, SERVER_STATE_NODE_ID), .attribute_id = ATTRIBUTE_VALUE } };
	ReadRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .timestamps_to_return = TimestampsToReturn.NEITHER, .nodes_to_read = &node };
	ByteBuf b;
	b.init(self.allocator, 128);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, READ_REQUEST_ENCODING_ID))!;
	e.put_read_request(req)!;
	self.queue_encoded(self.allocator, now, handle, PendingKind.KEEPALIVE, READ_RESPONSE_ENCODING_ID, 1, b.bytes())!;
	self.keepalive_pending = true;
}

fn void? Machine.on_keepalive(&self, sz idx, Message* m, sz after_tid, Now now)
{
	@pool()
	{
		Decoder d = decoder(m.body[after_tid..], tmem, self.config.limits);
		ReadResponse r = d.get_read_response()!;
		if (d.remaining() != 0 || r.results.len != 1) return BAD_RESPONSE~;
	};
	self.remove_pending(idx);
	self.keepalive_pending = false;
	self.last_activity_ms = now.mono_ms;
}

fn void? Machine.queue_close_session(&self, Now now)
{
	uint handle = self.alloc_handle();
	CloseSessionRequest req = { .request_header = self.request_header(now, handle, self.config.request_timeout_ms), .delete_subscriptions = true };
	ByteBuf b;
	b.init(self.allocator, 64);
	defer b.free();
	Encoder e = encoder(&b);
	e.put_nodeid(nodeid_num(0, CLOSE_SESSION_REQUEST_ENCODING_ID))!;
	e.put_close_session_request(req)!;
	self.queue_encoded(self.allocator, now, handle, PendingKind.CLOSE_SESSION, CLOSE_SESSION_RESPONSE_ENCODING_ID, 0, b.bytes())!;
}
