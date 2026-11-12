module uagen;
import std::collections::list;
import std::collections::set;
import std::encoding::xml;

fn String strip_prefix(String s)
{
	if (try idx = s.index_of(":"))
	{
		return s[idx + 1..];
	}
	return s;
}

fn void? parse_bsd(TypeTable* table, String content)
{
	sz stack_size = 128 * 1024;
	XmlDocument*? doc = xml::parse(table.allocator, content, stack_size);
	if (catch err = doc)
	{
		set_last_error("XML parsing failed");
		return UAGEN_XML_ERROR~;
	}
	table.doc = doc;

	if (doc.root == null)
	{
		set_last_error("XML document has no root");
		return UAGEN_XML_ERROR~;
	}

	foreach (child : doc.root.children)
	{
		if (child == null) continue;
		String tag = strip_prefix(child.name);

		if (tag == "StructuredType")
		{
			String name = child.attr("Name") ?? "";
			if (name.len == 0) continue;
			String base_type = child.attr("BaseType") ?? "";

			StructuredType* st = alloc::alloc(table.allocator, StructuredType);
			*st = {};
			st.name = name;
			st.base_type = base_type;
			st.fields.init(table.allocator);

			// First pass: collect length fields linked by LengthField attribute
			HashSet{String} length_fields;
			length_fields.init(tmem);
			defer length_fields.free();

			foreach (fnode : child.children)
			{
				if (fnode == null) continue;
				if (strip_prefix(fnode.name) != "Field") continue;

				// Record field attribute names
				foreach (k : fnode.attributes.key_iter())
				{
					if (!table.field_attrib_names.contains(k))
					{
						table.field_attrib_names.add(k);
					}
				}

				if (try lf = fnode.attr("LengthField"))
				{
					if (lf.len > 0)
					{
						length_fields.add(lf);
					}
				}
			}

			// Second pass: add members, skipping length fields (C201)
			foreach (fnode : child.children)
			{
				if (fnode == null) continue;
				if (strip_prefix(fnode.name) != "Field") continue;

				String fname = fnode.attr("Name") ?? "";
				if (fname.len == 0) continue;

				// C201: NoOf<Field> length fields precede their array and must not become struct members
				if (length_fields.contains(fname))
				{
					continue;
				}

				Field f;
				f.name = fname;
				f.type_name = strip_prefix(fnode.attr("TypeName") ?? "");
				f.length_field = fnode.attr("LengthField") ?? "";
				f.is_array = f.length_field.len > 0;
				f.switch_field = fnode.attr("SwitchField") ?? "";
				f.switch_value = fnode.attr("SwitchValue") ?? "";
				f.switch_operand = fnode.attr("SwitchOperand") ?? "";
				f.length = fnode.attr("Length") ?? "";
				f.source_type = fnode.attr("SourceType") ?? "";

				st.fields.push(f);
			}

			table.structures.set(name, st);
			table.struct_names.push(name);
		}
		else if (tag == "EnumeratedType")
		{
			String name = child.attr("Name") ?? "";
			if (name.len == 0) continue;

			EnumeratedType* en = alloc::alloc(table.allocator, EnumeratedType);
			*en = {};
			en.name = name;
			en.length_in_bits = 32;
			if (try bits_str = child.attr("LengthInBits"))
			{
				if (try b = string::to_integer{int}(bits_str))
				{
					en.length_in_bits = b;
				}
			}
			en.values.init(table.allocator);

			foreach (vnode : child.children)
			{
				if (vnode == null) continue;
				if (strip_prefix(vnode.name) != "EnumeratedValue") continue;

				String vname = vnode.attr("Name") ?? "";
				long val = 0;
				if (try val_str = vnode.attr("Value"))
				{
					if (try parsed_val = string::to_integer{long}(val_str))
					{
						val = parsed_val;
					}
				}
				EnumValue ev = { .name = vname, .value = val };
				en.values.push(ev);
			}

			table.enums.set(name, en);
			table.enum_names.push(name);
		}
		else if (tag == "OpaqueType")
		{
			String name = child.attr("Name") ?? "";
			if (name.len > 0)
			{
				table.opaques.add(name);
				table.opaque_names.push(name);
			}
		}
	}
}
