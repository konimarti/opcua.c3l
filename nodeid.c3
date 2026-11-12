module opcua;
import std::encoding::base64;

fn NodeId nodeid_num(ushort ns, uint id) => { .ns = ns, .kind = NUMERIC, .num = id };
fn NodeId nodeid_str(ushort ns, String id) => { .ns = ns, .kind = STRING, .str = id };

// Identity is (ns, kind, value): i=5 is the same node whichever wire encoding carried it; String ids are case sensitive
// (10000-3 8.2). A null and an empty String identifier are the same identifier.
fn bool nodeid_equals(NodeId a, NodeId b)
{
	if (a.ns != b.ns || a.kind != b.kind) return false;
	switch (a.kind)
	{
		case NUMERIC: return a.num == b.num;
		case STRING: return (char[])a.str == (char[])b.str;
		case GUID: return guid_equals(a.guid, b.guid);
		case OPAQUE: return a.bytes == b.bytes;
	}
}

fn bool guid_equals(Guid a, Guid b)
{
	return a.d1 == b.d1 && a.d2 == b.d2 && a.d3 == b.d3 && a.d4 == b.d4;
}

// FNV-1a over (ns, kind, value); consistent with nodeid_equals.
fn ulong nodeid_hash(NodeId id)
{
	ulong h = 0xcbf29ce484222325;
	h = fnv_byte(h, (char)id.ns);
	h = fnv_byte(h, (char)(id.ns >> 8));
	h = fnv_byte(h, (char)id.kind.ordinal);
	switch (id.kind)
	{
		case NUMERIC:
			for (int i = 0; i < 4; i++) h = fnv_byte(h, (char)(id.num >> (i * 8)));
		case STRING:
			foreach (c : (char[])id.str) h = fnv_byte(h, c);
		case GUID:
			for (int i = 0; i < 4; i++) h = fnv_byte(h, (char)(id.guid.d1 >> (i * 8)));
			h = fnv_byte(h, (char)id.guid.d2);
			h = fnv_byte(h, (char)(id.guid.d2 >> 8));
			h = fnv_byte(h, (char)id.guid.d3);
			h = fnv_byte(h, (char)(id.guid.d3 >> 8));
			foreach (c : id.guid.d4) h = fnv_byte(h, c);
		case OPAQUE:
			foreach (c : id.bytes) h = fnv_byte(h, c);
	}
	return h;
}

fn ulong fnv_byte(ulong h, char b) @local => (h ^ (ulong)b) * 0x100000001b3;

// ---------- text form (10000-6 5.3.1.10): [ns=<n>;]i=<n> | s=<text> | g=<guid> | b=<base64> ----------

fn uint? parse_decimal(String s, uint max) @local
{
	if (s.len == 0) return BAD_NODEID~;
	ulong v = 0;
	foreach (c : (char[])s)
	{
		if (c < '0' || c > '9') return BAD_NODEID~;
		v = v * 10 + (ulong)(c - '0');
		if (v > max) return BAD_NODEID~;
	}
	return (uint)v;
}

fn int hex_digit(char c) @local
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// Reads `digits` hex digits from s starting at `at` (no bounds slack: the caller checked the length).
fn ulong? parse_hex(String s, sz at, sz digits) @local
{
	ulong v = 0;
	for (sz i = 0; i < digits; i++)
	{
		int d = hex_digit(s[at + i]);
		if (d < 0) return BAD_NODEID~;
		v = (v << 4) | (ulong)d;
	}
	return v;
}

// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
fn Guid? parse_guid(String s) @local
{
	if (s.len == 38 && s[0] == '{' && s[37] == '}') s = s[1:36];
	if (s.len != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') return BAD_NODEID~;
	Guid g;
	g.d1 = (uint)parse_hex(s, 0, 8)!;
	g.d2 = (ushort)parse_hex(s, 9, 4)!;
	g.d3 = (ushort)parse_hex(s, 14, 4)!;
	g.d4[0] = (char)parse_hex(s, 19, 2)!;
	g.d4[1] = (char)parse_hex(s, 21, 2)!;
	for (sz i = 0; i < 6; i++) g.d4[2 + i] = (char)parse_hex(s, 24 + i * 2, 2)!;
	return g;
}

fn NodeId? parse_nodeid(String text, Allocator allocator)
{
	String rest = text;
	NodeId id;
	if (rest.len >= 3 && rest[0] == 'n' && rest[1] == 's' && rest[2] == '=')
	{
		sz semi = 0;
		bool found = false;
		for (sz i = 3; i < rest.len; i++)
		{
			if (rest[i] == ';') { semi = i; found = true; break; }
		}
		if (!found) return BAD_NODEID~;
		id.ns = (ushort)parse_decimal(rest[3:semi - 3], 65535)!;
		rest = rest[semi + 1..];
	}
	if (rest.len < 2 || rest[1] != '=') return BAD_NODEID~;
	String value = rest[2..];
	switch (rest[0])
	{
		case 'i':
			id.kind = NUMERIC;
			id.num = parse_decimal(value, uint::max)!;
		case 's':
			id.kind = STRING;
			char[] copy = alloc::alloc_array_try(allocator, char, value.len)!;
			if (value.len > 0) mem::copy(copy.ptr, value.ptr, value.len);
			id.str = value.len == 0 ? empty_string() : (String)copy;
		case 'g':
			id.kind = GUID;
			id.guid = parse_guid(value)!;
		case 'b':
			id.kind = OPAQUE;
			char[]? raw = base64::decode(allocator, (char[])value);
			if (catch raw) return BAD_NODEID~;
			id.bytes = raw.len == 0 ? empty_bytes() : raw;
		default:
			return BAD_NODEID~;
	}
	return id;
}

fn String nodeid_to_string(NodeId id, Allocator allocator)
{
	String prefix = id.ns == 0 ? "" : string::format(tmem, "ns=%d;", id.ns);
	switch (id.kind)
	{
		case NUMERIC: return string::format(allocator, "%si=%d", prefix, id.num);
		case STRING: return string::format(allocator, "%ss=%s", prefix, id.str);
		case GUID:
			Guid g = id.guid;
			return string::format(allocator, "%sg=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", prefix, g.d1, g.d2, g.d3,
				g.d4[0], g.d4[1], g.d4[2], g.d4[3], g.d4[4], g.d4[5], g.d4[6], g.d4[7]);
		case OPAQUE: return string::format(allocator, "%sb=%s", prefix, base64::encode(tmem, id.bytes));
	}
}
