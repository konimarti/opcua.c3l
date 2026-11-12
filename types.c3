module opcua;

// Built-in types of OPC 10000-6 5.1.2 / 5.2.2 that the codec handles so far.

typedef StatusCode = uint;                 // 10000-4 7.39
const StatusCode STATUS_GOOD = (StatusCode)0;

// Null versus empty: String, char[] (ByteString) and arrays are NULL when ptr == null (the zero value, so a default
// initialised request field encodes as -1) and EMPTY when ptr != null and len == 0. The encoder writes -1 / 0 accordingly and
// the decoder returns the same distinction. Use these helpers, never `len == 0`, when the difference matters.
fn bool is_null(String s) => s.ptr == null;
fn String null_string() { String s; return s; }
fn String empty_string() => (String)"";
fn bool bytes_is_null(char[] b) => b.ptr == null;
fn char[] null_bytes() { char[] b; return b; }
fn char[] empty_bytes() { String s = ""; return s.ptr[:0]; }

struct Guid
{
	uint d1;
	ushort d2;
	ushort d3;
	char[8] d4;
}

enum NodeIdKind : char { NUMERIC, STRING, GUID, OPAQUE }

struct NodeId
{
	ushort ns;
	NodeIdKind kind;
	union
	{
		uint num;
		String str;      // STRING
		char[] bytes;    // OPAQUE
		Guid guid;
	}
}

// StatusCode helpers (10000-4 7.39: top two bits = severity: 00 Good, 01 Uncertain, 10/11 Bad; the low 16 bits are info
// bits, so "good" is decided by severity, never by == 0)
fn bool status_is_good(StatusCode s) => ((uint)s >> 30) == 0;
fn bool status_is_uncertain(StatusCode s) => ((uint)s >> 30) == 1;
fn bool status_is_bad(StatusCode s) => ((uint)s >> 30) >= 2;
