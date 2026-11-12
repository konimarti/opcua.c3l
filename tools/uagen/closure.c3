module uagen;
import std::collections::list;
import std::collections::set;
import std::sort;

fn bool is_builtin(String name)
{
	String[*] builtins = {
		"Boolean", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
		"Float", "Double", "String", "DateTime", "Guid", "ByteString", "XmlElement",
		"NodeId", "ExpandedNodeId", "StatusCode", "QualifiedName", "LocalizedText",
		"ExtensionObject", "DataValue", "Variant", "DiagnosticInfo",
		"Char", "CharArray"
	};
	foreach (b : builtins)
	{
		if (name == b) return true;
	}
	return false;
}

fn int string_cmp(String* a, String* b)
{
	return a.compare_to(*b);
}

fn String[]? compute_closure(TypeTable* table, Allocator allocator, String[] roots)
{
	List{String} queue;
	queue.init(tmem);
	defer queue.free();

	HashSet{String} visited;
	visited.init(tmem);
	defer visited.free();

	HashSet{String} closure_set;
	closure_set.init(tmem);
	defer closure_set.free();

	foreach (r : roots)
	{
		String clean = strip_prefix(r.trim());
		if (clean.len > 0)
		{
			queue.push(clean);
		}
	}

	while (queue.len() > 0)
	{
		String curr = queue.pop_first()!!;
		String clean = strip_prefix(curr);
		if (visited.contains(clean)) continue;
		visited.add(clean);

		if (is_builtin(clean)) continue;

		if (table.structures.has_key(clean))
		{
			StructuredType* st = table.structures.get(clean)!!;

			foreach (f : st.fields)
			{
				// C202: switch/bit/optional fields -> hard error, never guessed
				if (f.switch_field.len > 0 || f.switch_value.len > 0 || f.switch_operand.len > 0)
				{
					String msg = string::tformat("Unsupported switch/optional field '%s' in type '%s'", f.name, st.name);
					set_last_error(msg);
					return UAGEN_UNSUPPORTED_CONSTRUCT~;
				}
				if (f.length.len > 0)
				{
					String msg = string::tformat("Unsupported bit field '%s' in type '%s'", f.name, st.name);
					set_last_error(msg);
					return UAGEN_UNSUPPORTED_CONSTRUCT~;
				}

				// C206: unknown type -> hard error naming type and field
				String ftype = strip_prefix(f.type_name);
				if (ftype.len == 0)
				{
					String msg = string::tformat("Empty field type for '%s.%s'", st.name, f.name);
					set_last_error(msg);
					return UAGEN_UNKNOWN_TYPE~;
				}

				if (!is_builtin(ftype) && !table.structures.has_key(ftype) && !table.enums.has_key(ftype))
				{
					String msg = string::tformat("Unknown type '%s' in field '%s.%s'", ftype, st.name, f.name);
					set_last_error(msg);
					return UAGEN_UNKNOWN_TYPE~;
				}

				if (!visited.contains(ftype))
				{
					queue.push(ftype);
				}
			}

			closure_set.add(clean);
		}
		else if (table.enums.has_key(clean))
		{
			EnumeratedType* en = table.enums.get(clean)!!;
			if (en.length_in_bits != 8 && en.length_in_bits != 16 && en.length_in_bits != 32)
			{
				String msg = string::tformat("Unsupported enum bit length %d in type '%s'", en.length_in_bits, en.name);
				set_last_error(msg);
				return UAGEN_UNSUPPORTED_CONSTRUCT~;
			}
			closure_set.add(clean);
		}
		else
		{
			String msg = string::tformat("Unknown root type '%s'", clean);
			set_last_error(msg);
			return UAGEN_UNKNOWN_TYPE~;
		}
	}

	String[] result = alloc::alloc_array(allocator, String, closure_set.len());
	sz idx = 0;
	foreach (name : closure_set.tvalues())
	{
		result[idx++] = name;
	}

	sort::quicksort(result, &string_cmp);
	return result;
}

struct SkippedType
{
	String name;
	String reason;
}

fn int skipped_cmp(SkippedType* a, SkippedType* b)
{
	return a.name.compare_to(b.name);
}

fn SkippedType[] get_skipped_types(TypeTable* table, Allocator allocator, HashSet{String}* closure_set)
{
	List{SkippedType} list;
	list.init(tmem);
	defer list.free();

	// Check structures
	foreach (st : table.structures.value_iter())
	{
		if (closure_set.contains(st.name)) continue;

		String reason = "";
		// Check for switch/optional fields
		foreach (f : st.fields)
		{
			if (f.switch_field.len > 0)
			{
				reason = string::tformat("switch/optional field (%s) on %s", f.switch_field, f.name);
				break;
			}
			if (f.switch_value.len > 0)
			{
				reason = string::tformat("switch value (%s) on %s", f.switch_value, f.name);
				break;
			}
			if (f.length.len > 0)
			{
				reason = string::tformat("fixed bit length (%s) on %s", f.length, f.name);
				break;
			}
		}

		// Check base type
		if (reason.len == 0 && st.base_type.len > 0 && st.base_type != "ua:ExtensionObject")
		{
			reason = string::tformat("BaseType (%s) != ua:ExtensionObject", st.base_type);
		}

		if (reason.len == 0)
		{
			reason = "not in roots closure (v1 whitelist)";
		}

		SkippedType st_entry = { .name = st.name, .reason = reason };
		list.push(st_entry);
	}

	// Check enums
	foreach (en : table.enums.value_iter())
	{
		if (closure_set.contains(en.name)) continue;

		String reason = "";
		if (en.length_in_bits != 8 && en.length_in_bits != 16 && en.length_in_bits != 32)
		{
			reason = string::tformat("LengthInBits=%d", en.length_in_bits);
		}
		else
		{
			reason = "not in roots closure (v1 whitelist)";
		}

		SkippedType en_entry = { .name = en.name, .reason = reason };
		list.push(en_entry);
	}

	// Check opaques
	foreach (op_name : table.opaques.tvalues())
	{
		SkippedType op_entry = { .name = op_name, .reason = "opaque type (hand-written built-in)" };
		list.push(op_entry);
	}

	SkippedType[] result = alloc::alloc_array(allocator, SkippedType, list.len());
	for (sz i = 0; i < list.len(); i++)
	{
		result[i] = list[i];
	}

	sort::quicksort(result, &skipped_cmp);
	return result;
}
