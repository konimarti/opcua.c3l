module opcua;

// A scripted peer for the machine tests. Every reply is built from hand-written hex templates (not from the Encoder),
// so an encoder bug cannot cancel against a decoder bug.

const String NONE_URI_FULL = "2F 00 00 00 68 74 74 70 3A 2F 2F 6F 70 63 66 6F 75 6E 64 61 74 69 6F 6E 2E 6F 72 67 2F 55 41 2F 53 65 63 75 72 69 74 79 50 6F 6C 69 63 79 23 4E 6F 6E 65";
const String OTHER_URI_FULL = "04 00 00 00 75 72 6E 3A";
const String RESPONSE_HEADER_TAIL = "00 FF FF FF FF 00 00 00";             // DiagnosticInfo none, StringTable null, AdditionalHeader null
const String ID_READ_RESPONSE = "01 00 7A 02";                                // ReadResponse, an arbitrary service answer
const String ID_SERVICE_FAULT_HEX = "01 00 8D 01";

fn String le32(uint v) => string::tformat("%02X %02X %02X %02X", v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, v >> 24);

fn char[] fs_frame(String head, String rest)
{
	char[] r = unhex(rest);
	return cat(unhex(string::tformat("%s %s", head, le32((uint)(8 + r.len)))), r);
}

struct FakeServer
{
	uint channel;
	uint seq;            // next sequence number it sends
}

fn FakeServer fake_server(uint channel = 7, uint first_seq = 77) => { channel, first_seq };

fn char[] FakeServer.ack(&self, uint recv = 65536, uint send = 65536, uint max_msg = 0, uint max_chunks = 0, uint version = 0)
{
	return fs_frame("41 43 4B 46", string::tformat("%s %s %s %s %s", le32(version), le32(recv), le32(send), le32(max_msg), le32(max_chunks)));
}

fn char[] FakeServer.error(&self, uint status = 0x80800000)
{
	return fs_frame("45 52 52 46", string::tformat("%s 01 00 00 00 78", le32(status)));
}

// OpenSecureChannelResponse in an OPN frame (the B5 layout; layout of a real response: asymmetric header, sequence header, type id 449,
// ResponseHeader, protocol version, security token, server nonce).
fn char[] FakeServer.opn_response(&self, uint request_id, uint handle, uint channel, uint token, uint lifetime, String policy = NONE_URI_FULL, uint result = 0)
{
	uint s = self.seq++;
	return fs_frame("4F 50 4E 46", string::tformat("%s %s FF FF FF FF FF FF FF FF %s %s 01 00 C1 01 00 00 00 00 00 00 00 00 %s %s %s 00 00 00 00 %s %s 00 00 00 00 00 00 00 00 %s FF FF FF FF",
		le32(channel), policy, le32(s), le32(request_id), le32(handle), le32(result), RESPONSE_HEADER_TAIL, le32(channel), le32(token), le32(lifetime)));
}

// A MSG chunk carrying a service response: `type` is the type id hex, `payload` the service body after the ResponseHeader.
fn char[] FakeServer.msg(&self, uint request_id, uint handle, uint token, String type = ID_READ_RESPONSE, String payload = "", uint result = 0)
{
	uint s = self.seq++;
	return fs_frame("4D 53 47 46", string::tformat("%s %s %s %s %s 00 00 00 00 00 00 00 00 %s %s %s %s", le32(self.channel), le32(token), le32(s), le32(request_id), type, le32(handle), le32(result), RESPONSE_HEADER_TAIL, payload));
}

fn char[] FakeServer.service_fault(&self, uint request_id, uint handle, uint token, uint result)
{
	return self.msg(request_id, handle, token, ID_SERVICE_FAULT_HEX, "", result);
}

// ---------- session and service templates ----------
const String ID_CREATE_SESSION_RESPONSE = "01 00 D0 01";
const String ID_ACTIVATE_SESSION_RESPONSE = "01 00 D6 01";
const String ID_CLOSE_SESSION_RESPONSE = "01 00 DC 01";
const String ID_WRITE_RESPONSE = "01 00 A4 02";
const String ID_CALL_RESPONSE = "01 00 CB 02";
const String ID_PUBLISH_RESPONSE = "01 00 3D 03";
const String ID_READ_REQUEST = "01 00 77 02";
const String NULL4 = "FF FF FF FF";
const String DOUBLE_60000 = "00 00 00 00 00 4C ED 40";
const String DOUBLE_90000 = "00 00 00 00 00 F9 F5 40";
const String DOUBLE_NAN = "00 00 00 00 00 00 F8 7F";
const String DOUBLE_ZERO = "00 00 00 00 00 00 00 00";
const String DOUBLE_MINUS = "00 00 00 00 00 00 14 C0";
const String DOUBLE_INF = "00 00 00 00 00 00 F0 7F";
const String READ_PAYLOAD = "01 00 00 00 01 06 2A 00 00 00 00 00 00 00";                   // one DataValue (Int32 42), no diagnostics
const String WRITE_PAYLOAD = "01 00 00 00 00 00 00 00 00 00 00 00";
const String CALL_PAYLOAD = "01 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00";
const String ACTIVATE_PAYLOAD = "FF FF FF FF FF FF FF FF FF FF FF FF";

// A String as it appears on the wire: length and ASCII bytes, as hex.
fn String str_hex(String s)
{
	DString d = dstring::temp();
	d.appendf("%s", le32((uint)s.len));
	foreach (c : s) d.appendf(" %02X", c);
	return d.str_view();
}

// RequestHeader as hex: `auth` is the hex of the AuthenticationToken NodeId.
fn String request_header_hex(String auth, uint handle, uint timeout_hint)
{
	return string::tformat("%s 00 00 00 00 00 00 00 00 %s 00 00 00 00 FF FF FF FF %s 00 00 00", auth, le32(handle), le32(timeout_hint));
}

// One EndpointDescription (mode None, policy None) with an anonymous and a user name policy; `user_policy_uri` is the hex of
// the user name policy's SecurityPolicyUri string.
fn String endpoint_hex(String user_policy_uri = NULL4, String policy_uri = NONE_URI_FULL, uint mode = 1, bool offer_user = true)
{
	String users = offer_user ? string::tformat("02 00 00 00 04 00 00 00 61 6E 6F 6E 00 00 00 00 %s %s %s 04 00 00 00 75 73 65 72 01 00 00 00 %s %s %s", NULL4, NULL4, NULL4, NULL4, NULL4, user_policy_uri) : string::tformat("01 00 00 00 04 00 00 00 61 6E 6F 6E 00 00 00 00 %s %s %s", NULL4, NULL4, NULL4);
	return string::tformat("01 00 00 00 75  01 00 00 00 73 %s 00  00 00 00 00 %s %s %s  %s  %s  %s  %s  %s  00", NULL4, NULL4, NULL4, NULL4, NULL4, le32(mode), policy_uri, users, NULL4);
}

fn String session_payload(String timeout = DOUBLE_60000, String endpoints = "", String session_id = "01 01 64 00", uint max_request = 0)
{
	String eps = endpoints.len == 0 ? string::tformat("01 00 00 00 %s", endpoint_hex()) : endpoints;
	return string::tformat("%s 01 01 65 00 %s %s %s %s %s %s %s %s", session_id, timeout, NULL4, NULL4, eps, NULL4, NULL4, NULL4, le32(max_request));
}

fn char[] FakeServer.create_session_response(&self, uint request_id, uint handle, uint token, String payload = "")
{
	return self.msg(request_id, handle, token, ID_CREATE_SESSION_RESPONSE, payload.len == 0 ? session_payload() : payload);
}

fn char[] FakeServer.activate_response(&self, uint request_id, uint handle, uint token, uint result = 0)
{
	return self.msg(request_id, handle, token, ID_ACTIVATE_SESSION_RESPONSE, ACTIVATE_PAYLOAD, result);
}

// ---------- discovery, browse and translate templates ----------
const String ID_GET_ENDPOINTS_RESPONSE = "01 00 AF 01";
const String ID_FIND_SERVERS_RESPONSE = "01 00 A9 01";
const String ID_FIND_SERVERS_ON_NETWORK_RESPONSE = "01 00 B1 2F";
const String ID_BROWSE_RESPONSE = "01 00 12 02";
const String ID_BROWSE_NEXT_RESPONSE = "01 00 18 02";
const String ID_TRANSLATE_RESPONSE = "01 00 2D 02";
const String B10_GET_ENDPOINTS = "4D 53 47 46 5D 00 00 00 07 00 00 00 02 00 00 00 05 00 00 00 02 00 00 00 01 00 AC 01 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 FF FF FF FF 10 27 00 00 00 00 00 18 00 00 00 6F 70 63 2E 74 63 70 3A 2F 2F 6C 6F 63 61 6C 68 6F 73 74 3A 34 38 34 30 FF FF FF FF FF FF FF FF";

// A response whose body after the type id is given as hex (header included): for malformed headers.
fn char[] FakeServer.msg_body(&self, uint request_id, uint token, String type, String body)
{
	uint s = self.seq++;
	return fs_frame("4D 53 47 46", string::tformat("%s %s %s %s %s %s", le32(self.channel), le32(token), le32(s), le32(request_id), type, body));
}

// One chunk of a message (kind 'C' or 'F') with this server's channel, a fresh sequence number and the given body.
fn char[] FakeServer.chunk(&self, char kind, uint request_id, uint token, char[] body)
{
	uint s = self.seq++;
	char[] head = unhex(string::tformat("4D 53 47 00 00 00 00 00 %s %s %s %s", le32(self.channel), le32(token), le32(s), le32(request_id)));
	head[3] = kind;
	char[] frame = cat(head, body);
	frame[4] = (char)(frame.len & 0xFF);
	frame[5] = (char)(frame.len >> 8);
	return frame;
}

// One ReferenceDescription as hex: the reference type i=33, forward, target i=85, browse and display name `name`, Object.
fn String ref_hex(String name)
{
	return string::tformat("00 21 01 00 55 00 00 %s 02 %s 01 00 00 00 00 00", str_hex(name), str_hex(name));
}

fn String browse_payload(String continuation, uint refs, String refs_hex)
{
	return string::tformat("01 00 00 00 00 00 00 00 %s %s %s 00 00 00 00", continuation, le32(refs), refs_hex);
}
