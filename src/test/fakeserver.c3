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
