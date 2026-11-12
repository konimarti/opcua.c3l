module opcua;

// Hook for Sign / SignAndEncrypt (planned, not built in v1). ChunkReader and ChunkWriter take a ChunkSecurity value
// (null = SecurityNone), so adding a policy later is an implementation, not an API change.
//
// Header lengths: `protect` and `unprotect` get the number of bytes in front of the sequence header (16 for MSG/CLO,
// 12 + the asymmetric header for OPN). `max_body` gets the number of bytes in front of the body, i.e. including the
// 8 byte sequence header (24 for MSG/CLO under None).
interface ChunkSecurity
{
	fn String policy_uri();
	fn MessageSecurityMode mode();
	// bytes added after the body of a chunk (padding + signature) for a body of `body_len`
	fn sz footer_len(sz body_len);
	// largest body that fits in a chunk of `total_chunk_size` with `header_len` bytes in front of the body
	fn sz max_body(sz total_chunk_size, sz header_len, bool asymmetric);
	// protect: chunk is header + sequence header + body; appends the footer and encrypts in place
	fn void? protect(ByteBuf* chunk, sz header_len, bool asymmetric);
	// verifies, decrypts and strips the footer; returns the plaintext span inside `chunk` (from the sequence header on)
	fn char[]? unprotect(char[] chunk, sz header_len, bool asymmetric);
	// certificate bytes / thumbprint for the asymmetric header (null ByteStrings under None)
	fn char[] sender_certificate();
	fn char[] receiver_thumbprint();
}

struct SecurityNone (ChunkSecurity) { char dummy; }
fn String SecurityNone.policy_uri(&self) @dynamic => POLICY_NONE;
fn MessageSecurityMode SecurityNone.mode(&self) @dynamic => MessageSecurityMode.NONE;
fn sz SecurityNone.footer_len(&self, sz body_len) @dynamic => 0;
fn sz SecurityNone.max_body(&self, sz total_chunk_size, sz header_len, bool asymmetric) @dynamic => total_chunk_size > header_len ? total_chunk_size - header_len : 0;
fn void? SecurityNone.protect(&self, ByteBuf* chunk, sz header_len, bool asymmetric) @dynamic {}
fn char[]? SecurityNone.unprotect(&self, char[] chunk, sz header_len, bool asymmetric) @dynamic
{
	if (header_len > chunk.len) return BAD_CHUNK~;
	return chunk[header_len..];
}
fn char[] SecurityNone.sender_certificate(&self) @dynamic => null_bytes();
fn char[] SecurityNone.receiver_thumbprint(&self) @dynamic => null_bytes();
