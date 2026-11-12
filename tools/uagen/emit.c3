module uagen;
import std::collections::list;
import std::collections::set;
import std::sort;

// Emitters: gen_types.c3 (structs and enums), gen_codec.c3 (Encoder.put_X / Decoder.get_X) and gen_ids.c3 (encoding ids,
// attribute ids, status code names). The output is a pure function of the schema files and the closure: sorted, no
// timestamps, no paths.

struct Builtin
{
	String ua;
	String c3;
	int min;           // smallest wire size of one value
	String put;        // call with `$` standing for the value
	String get_cast;   // cast written in front of the decode call
	String get_fn;
}

const Builtin[*] BUILTINS = {
	{ "Boolean", "bool", 1, "put_bool($)", "", "get_bool" },
	{ "SByte", "ichar", 1, "put_u8((char)$)", "(ichar)", "get_u8" },
	{ "Byte", "char", 1, "put_u8($)", "", "get_u8" },
	{ "Int16", "short", 2, "put_u16((ushort)$)", "(short)", "get_u16" },
	{ "UInt16", "ushort", 2, "put_u16($)", "", "get_u16" },
	{ "Int32", "int", 4, "put_u32((uint)$)", "(int)", "get_u32" },
	{ "UInt32", "uint", 4, "put_u32($)", "", "get_u32" },
	{ "Int64", "long", 8, "put_u64((ulong)$)", "(long)", "get_u64" },
	{ "UInt64", "ulong", 8, "put_u64($)", "", "get_u64" },
	{ "Float", "float", 4, "put_f32($)", "", "get_f32" },
	{ "Double", "double", 8, "put_f64($)", "", "get_f64" },
	{ "String", "String", 4, "put_string($)", "", "get_string" },
	{ "XmlElement", "String", 4, "put_string($)", "", "get_string" },
	{ "DateTime", "UaDateTime", 8, "put_datetime($)", "", "get_datetime" },
	{ "Guid", "Guid", 16, "put_guid($)", "", "get_guid" },
	{ "ByteString", "char[]", 4, "put_bytestring($)", "", "get_bytestring" },
	{ "NodeId", "NodeId", 2, "put_nodeid($)", "", "get_nodeid" },
	{ "ExpandedNodeId", "ExpandedNodeId", 2, "put_expanded_nodeid($)", "", "get_expanded_nodeid" },
	{ "StatusCode", "StatusCode", 4, "put_u32((uint)$)", "(StatusCode)", "get_u32" },
	{ "QualifiedName", "QualifiedName", 6, "put_qualified_name($)", "", "get_qualified_name" },
	{ "LocalizedText", "LocalizedText", 1, "put_localized_text($)", "", "get_localized_text" },
	{ "ExtensionObject", "ExtensionObject", 3, "put_extension_object($)", "", "get_extension_object" },
	{ "DataValue", "DataValue", 1, "put_data_value($)", "", "get_data_value" },
	{ "Variant", "Variant", 1, "put_variant($)", "", "get_variant" },
	{ "DiagnosticInfo", "DiagnosticInfo", 1, "put_diagnostic_info($)", "", "get_diagnostic_info" },
};

// C3 keywords and names that would clash: they get a trailing underscore (field `Type` -> `type_`).
const String[*] RESERVED = {
	"alias", "any", "asm", "assert", "attrdef", "bool", "break", "case", "catch", "char", "const", "constdef", "continue",
	"default", "defer", "distinct", "do", "double", "else", "enum", "extern", "false", "fault", "faultdef", "float", "fn",
	"for", "foreach", "if", "import", "inline", "int", "interface", "ichar", "iptr", "isz", "long", "macro", "module",
	"nextcase", "null", "return", "self", "short", "static", "struct", "switch", "sz", "tlocal", "true", "try", "type",
	"typedef", "typeid", "uint", "ulong", "union", "uptr", "usz", "ushort", "var", "void", "while",
};

fn bool is_upper(char c) => c >= 'A' && c <= 'Z';
fn bool is_lower(char c) => c >= 'a' && c <= 'z';
fn bool is_digit(char c) => c >= '0' && c <= '9';

// CamelCase -> snake_case; acronyms stay together (`ServerURI` -> `server_uri`).
fn String snake_case(String s)
{
	DString d;
	d.init(tmem);
	foreach (i, c : s)
	{
		if (is_upper(c))
		{
			if (i > 0)
			{
				char prev = s[i - 1];
				bool next_lower = i + 1 < s.len && is_lower(s[i + 1]);
				if (is_lower(prev) || is_digit(prev) || (is_upper(prev) && next_lower)) d.append_char('_');
			}
			d.append_char(c - 'A' + 'a');
		}
		else
		{
			d.append_char(c);
		}
	}
	return d.str_view();
}

fn String upper_snake(String s)
{
	String low = snake_case(s);
	DString d;
	d.init(tmem);
	foreach (c : low) d.append_char(is_lower(c) ? c - 'a' + 'A' : c);
	if (d.len() > 0 && is_digit(d.str_view()[0])) return string::tformat("V_%s", d.str_view());
	return d.str_view();
}

fn String escape_name(String s)
{
	foreach (r : RESERVED)
	{
		if (r == s) return string::tformat("%s_", s);
	}
	return s;
}

fn String field_name(String ua) => escape_name(snake_case(ua));

struct FieldKind
{
	String c3;
	int min;
	String put;
	String get_cast;
	String get_fn;
}

fn String subst(String tpl, String value)
{
	DString d;
	d.init(tmem);
	foreach (c : tpl)
	{
		if (c == '$')
		{
			d.append(value);
		}
		else
		{
			d.append_char(c);
		}
	}
	return d.str_view();
}

fn String? width_type(int bits, bool signed)
{
	switch (bits)
	{
		case 8: return signed ? "ichar" : "char";
		case 16: return signed ? "short" : "ushort";
		case 32: return signed ? "int" : "uint";
		default: return UAGEN_UNSUPPORTED_CONSTRUCT~;
	}
}

fn FieldKind? field_kind(TypeTable* t, String name, int depth = 0)
{
	if (depth > 32)
	{
		set_last_error("type nesting too deep (recursive structure?)");
		return UAGEN_UNSUPPORTED_CONSTRUCT~;
	}
	foreach (b : BUILTINS)
	{
		if (b.ua == name) return { b.c3, b.min, b.put, b.get_cast, b.get_fn };
	}
	if (t.enums.has_key(name))
	{
		EnumeratedType* en = t.enums.get(name)!!;
		int w = en.length_in_bits;
		String unsigned_t = width_type(w, false)!;
		String signed_t = width_type(w, true)!;
		String fn_name = string::tformat("get_u%d", w);
		if (en.is_option_set)
		{
			// OptionSet types stay plain integers: the bits are the caller's business
			return { unsigned_t, w / 8, string::tformat("put_u%d($)", w), "", fn_name };
		}
		return { name, w / 8, string::tformat("put_u%d((%s)(%s)$)", w, unsigned_t, signed_t), string::tformat("(%s)(%s)", name, signed_t), fn_name };
	}
	if (t.structures.has_key(name))
	{
		StructuredType* st = t.structures.get(name)!!;
		int min = 0;
		foreach (f : st.fields)
		{
			min += f.is_array ? 4 : field_kind(t, f.type_name, depth + 1)!.min;
		}
		if (min < 1) min = 1;
		String sn = snake_case(name);
		return { name, min, string::tformat("put_%s($)", sn), "", string::tformat("get_%s", sn) };
	}
	set_last_error(string::tformat("Unknown type '%s' during emission", name));
	return UAGEN_UNKNOWN_TYPE~;
}

fn void emit_header(DString* out, String source)
{
	out.append("// DO NOT EDIT. Generated by tools/uagen from the files in schema/; run `uagen --generate` to refresh.\n");
	foreach (line : source.tsplit("\n"))
	{
		String l = line.trim();
		if (l.len > 0) out.appendf("// Source: %s\n", l);
	}
	out.append("\nmodule opcua;\n");
}

// ---------- gen_types.c3 ----------
fn void? emit_types(TypeTable* t, String[] closure, String source, DString* out)
{
	emit_header(out, source);
	foreach (name : closure)
	{
		out.append("\n");
		if (t.enums.has_key(name))
		{
			EnumeratedType* en = t.enums.get(name)!!;
			if (en.is_option_set)
			{
				out.appendf("// %s is an OptionSet: fields of this type are plain unsigned integers.\n", name);
				continue;
			}
			out.appendf("constdef %s : %s\n{\n", name, width_type(en.length_in_bits, true)!);
			foreach (v : en.values) out.appendf("\t%s = %d,\n", upper_snake(v.name), v.value);
			out.append("}\n");
			continue;
		}
		StructuredType* st = t.structures.get(name)!;
		out.appendf("struct %s\n{\n", name);
		foreach (f : st.fields)
		{
			FieldKind k = field_kind(t, f.type_name)!;
			out.appendf("\t%s%s %s;\n", k.c3, f.is_array ? "[]" : "", field_name(f.name));
		}
		out.append("}\n");
	}
}

// ---------- gen_codec.c3 ----------
fn void? emit_codec(TypeTable* t, String[] closure, String source, DString* out)
{
	emit_header(out, source);
	foreach (name : closure)
	{
		if (!t.structures.has_key(name)) continue;
		StructuredType* st = t.structures.get(name)!!;
		String sn = snake_case(name);
		out.appendf("\nfn void? Encoder.put_%s(&self, %s v)\n{\n\tself.enter()!;\n\tdefer self.leave();\n", sn, name);
		foreach (f : st.fields)
		{
			FieldKind k = field_kind(t, f.type_name)!;
			String member = string::tformat("v.%s", field_name(f.name));
			if (f.is_array)
			{
				out.appendf("\tself.put_array_len(%s.len, %s.ptr == null)!;\n", member, member);
				out.appendf("\tforeach (x : %s) self.%s!;\n", member, subst(k.put, "x"));
			}
			else
			{
				out.appendf("\tself.%s!;\n", subst(k.put, member));
			}
		}
		out.append("}\n");
		out.appendf("\nfn %s? Decoder.get_%s(&self)\n{\n\tself.enter()!;\n\tdefer self.leave();\n\t%s v;\n", name, sn, name);
		foreach (f : st.fields)
		{
			FieldKind k = field_kind(t, f.type_name)!;
			String member = string::tformat("v.%s", field_name(f.name));
			String call = string::tformat("%sself.%s()!", k.get_cast, k.get_fn);
			if (f.is_array)
			{
				out.append("\t{\n");
				out.appendf("\t\tint n = self.get_array_len(%d)!;\n", k.min);
				out.append("\t\tif (n >= 0)\n\t\t{\n");
				out.appendf("\t\t\t%s[] items = new_slice(self.allocator, %s, n)!;\n", k.c3, k.c3);
				out.append("\t\t\tdefer catch alloc::free(self.allocator, items.ptr);\n");
				out.appendf("\t\t\tfor (int i = 0; i < n; i++) items[i] = %s;\n", call);
				out.appendf("\t\t\t%s = items;\n", member);
				out.append("\t\t}\n\t}\n");
			}
			else
			{
				out.appendf("\t%s = %s;\n", member, call);
			}
		}
		out.append("\treturn v;\n}\n");
	}
}

// ---------- gen_ids.c3 ----------
const String[*] ATTRIBUTE_NAMES = {
	"NodeId", "NodeClass", "BrowseName", "DisplayName", "Description", "WriteMask", "UserWriteMask", "IsAbstract",
	"Symmetric", "InverseName", "ContainsNoLoops", "EventNotifier", "Value", "DataType", "ValueRank", "ArrayDimensions",
	"AccessLevel", "UserAccessLevel", "MinimumSamplingInterval", "Historizing", "Executable", "UserExecutable",
	"DataTypeDefinition", "RolePermissions", "UserRolePermissions", "AccessRestrictions", "AccessLevelEx",
};

fn int status_cmp(StatusCodeEntry* a, StatusCodeEntry* b)
{
	if (a.code != b.code) return a.code < b.code ? -1 : 1;
	return a.name.compare_to(b.name);
}

fn void? emit_ids(TypeTable* t, String[] closure, NodeIdsTable* ids, StatusCodeTable* statuses, String source, DString* out)
{
	emit_header(out, source);
	out.append("\n// Binary encoding ids (the `_Encoding_DefaultBinary` rows of NodeIds.csv), namespace 0.\n");
	foreach (name : closure)
	{
		if (!t.structures.has_key(name)) continue;
		if (try id = ids.lookup(string::tformat("%s_Encoding_DefaultBinary", name)))
		{
			out.appendf("const uint %s_ENCODING_ID = %d;\n", upper_snake(name), id);
		}
	}
	out.append("\n// Attribute ids (10000-3 5.2 / 10000-4 5.10).\n");
	foreach (i, a : ATTRIBUTE_NAMES) out.appendf("const uint ATTRIBUTE_%s = %d;\n", upper_snake(a), i + 1);

	StatusCodeEntry[] sorted = alloc::alloc_array(tmem, StatusCodeEntry, statuses.entries.len());
	foreach (i, e : statuses.entries) sorted[i] = e;
	sort::quicksort(sorted, &status_cmp);
	out.append("\n// Name of a status code, from StatusCode.csv; the info bits (low 16 bits) are ignored.\n");
	out.append("fn String status_name(StatusCode s)\n{\n\tswitch ((uint)s & 0xFFFF0000)\n\t{\n");
	HashSet{uint} seen;
	seen.init(tmem);
	foreach (e : sorted)
	{
		uint masked = e.code & 0xFFFF0000;
		if (seen.contains(masked)) continue;
		seen.add(masked);
		out.appendf("\t\tcase 0x%08X: return \"%s\";\n", masked, e.name);
	}
	out.append("\t\tdefault: return \"Unknown\";\n\t}\n}\n");
}
