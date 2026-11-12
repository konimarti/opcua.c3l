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

typedef UaDateTime = long;                 // 100 ns ticks since 1601-01-01 UTC (10000-6 5.2.2.5); not std::time::DateTime

struct ExpandedNodeId
{
	NodeId id;
	String namespace_uri;   // null = flag 0x80 absent; empty non-null = flag set with an empty URI
	uint server_index;      // 0 = flag 0x40 absent
}

struct QualifiedName
{
	ushort ns;
	String name;
}

struct LocalizedText
{
	String locale;          // null = absent
	String text;            // null = absent
}

struct ExtensionObject
{
	NodeId type_id;      // the DefaultBinary encoding id as on the wire
	char encoding;       // 0 = no body, 1 = ByteString body, 2 = XmlElement body (kept as received)
	char[] body;         // raw body (null when encoding is 0 or the body length is -1)
}

// present holds the wire bits of the four Int32 fields (0x01 symbolic_id, 0x02 namespace_uri, 0x04 localized_text,
// 0x08 locale): zero is a valid string table index, so presence cannot be derived from the value. The other three
// fields are present when additional_info is not null, inner_status != 0 and inner != null.
struct DiagnosticInfo
{
	char present;
	int symbolic_id;
	int namespace_uri;
	int localized_text;
	int locale;
	String additional_info;
	StatusCode inner_status;
	DiagnosticInfo* inner;   // allocated from the decode allocator
}

// BuiltInType ids, 10000-6 5.1.2
constdef BuiltIn : char
{
	EMPTY = 0, BOOLEAN = 1, SBYTE = 2, BYTE = 3, INT16 = 4, UINT16 = 5, INT32 = 6, UINT32 = 7,
	INT64 = 8, UINT64 = 9, FLOAT = 10, DOUBLE = 11, STRING = 12, DATETIME = 13, GUID = 14,
	BYTESTRING = 15, XMLELEMENT = 16, NODEID = 17, EXPANDEDNODEID = 18, STATUSCODE = 19,
	QUALIFIEDNAME = 20, LOCALIZEDTEXT = 21, EXTENSIONOBJECT = 22, DATAVALUE = 23,
	VARIANT = 24, DIAGNOSTICINFO = 25,
}

union Scalar
{
	bool b;
	ichar i8;
	char u8;
	short i16;
	ushort u16;
	int i32;
	uint u32;
	long i64;
	ulong u64;
	float f32;
	double f64;
	String str;          // String, XmlElement
	char[] bytes;        // ByteString
	Guid guid;
	UaDateTime dt;
	StatusCode sc;
	NodeId* node_id;
	ExpandedNodeId* xnode_id;
	QualifiedName* qname;
	LocalizedText* ltext;
	ExtensionObject* ext;
	DataValue* dv;
	DiagnosticInfo* diag;
}

// Typed arrays: the slice that matches Variant.type is valid when is_array. Row-major for matrices.
union ArrayData
{
	bool[] b;
	ichar[] i8;
	char[] u8;
	short[] i16;
	ushort[] u16;
	int[] i32;
	uint[] u32;
	long[] i64;
	ulong[] u64;
	float[] f32;
	double[] f64;
	String[] str;
	char[][] bytes;
	Guid[] guid;
	UaDateTime[] dt;
	StatusCode[] sc;
	NodeId[] node_id;
	ExpandedNodeId[] xnode_id;
	QualifiedName[] qname;
	LocalizedText[] ltext;
	ExtensionObject[] ext;
	DataValue[] dv;
	Variant[] variant;
	DiagnosticInfo[] diag;
}

struct Variant
{
	BuiltIn type;         // EMPTY = null variant
	bool is_array;
	Scalar scalar;        // valid when !is_array
	ArrayData array;      // valid when is_array; a null slice = null array (length -1), empty non-null = length 0
	uint[] dims;          // ArrayDimensions, empty unless matrix
}

// DataValue has no stored mask. Encoding rule, purely from the fields: value present iff has_value; status iff != 0;
// source/server timestamp iff != 0; picoseconds iff != 0. Decoding an absent part leaves it 0 (Good / null time).
struct DataValue
{
	Variant value;
	bool has_value;
	StatusCode status;
	UaDateTime source_ts;
	ushort source_pico;
	UaDateTime server_ts;
	ushort server_pico;
}
