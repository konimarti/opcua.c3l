module uagen;
import std::io;
import std::io::file;
import std::collections::list;
import std::collections::set;

fn String? read_text_file(String path)
{
	char[]? bytes = file::load(mem, path);
	if (catch bytes) return UAGEN_FILE_ERROR~;
	return (String)bytes;
}

fn String[] load_roots(Allocator allocator, String roots_path)
{
	if (try content = read_text_file(roots_path))
	{
		defer mem::free(content.ptr);
		String[] raw_roots = content.tsplit("\n");
		List{String} list;
		list.init(tmem);
		foreach (r : raw_roots)
		{
			String trimmed = r.trim();
			if (trimmed.len > 0)
			{
				list.push(trimmed.copy(allocator));
			}
		}
		String[] res = alloc::alloc_array(allocator, String, list.len());
		for (sz i = 0; i < list.len(); i++)
		{
			res[i] = list[i];
		}
		return res;
	}
	return {};
}

fn int main(String[] args)
{
	bool list_types = false;
	bool list_unsupported = false;
	bool show_stats = false;

	String bsd_path = "schema/Opc.Ua.Types.bsd";
	String nodeids_path = "schema/NodeIds.csv";
	String statuscode_path = "schema/StatusCode.csv";
	String roots_path = "tools/uagen/roots.txt";

	for (sz i = 1; i < args.len; i++)
	{
		String arg = args[i];
		if (arg == "--list-types")
		{
			list_types = true;
		}
		else if (arg == "--list-unsupported")
		{
			list_unsupported = true;
		}
		else if (arg == "--stats")
		{
			show_stats = true;
		}
	}

	String? bsd_res = read_text_file(bsd_path);
	if (catch err = bsd_res)
	{
		io::printfn("Error: unable to load %s", bsd_path);
		return 1;
	}
	String bsd_content = bsd_res;
	defer mem::free(bsd_content.ptr);

	TypeTable table;
	table.init(mem);
	defer table.free();

	if (catch err = parse_bsd(&table, bsd_content))
	{
		io::printfn("Error: failed to parse %s: %s", bsd_path, last_error_msg);
		return 1;
	}

	String[] roots = load_roots(mem, roots_path);
	defer
	{
		foreach (r : roots) mem::free(r.ptr);
		mem::free(roots.ptr);
	}

	String[]? closure_res = compute_closure(&table, mem, roots);
	if (catch err = closure_res)
	{
		io::printfn("Error: closure computation failed: %s", last_error_msg);
		return 1;
	}
	String[] closure = closure_res;
	defer mem::free(closure.ptr);

	HashSet{String} closure_set;
	closure_set.init(tmem);
	defer closure_set.free();
	foreach (c : closure)
	{
		closure_set.add(c);
	}

	if (list_types)
	{
		foreach (t : closure)
		{
			io::printn(t);
		}
		io::printfn("Total closure types: %d", closure.len);
		return 0;
	}

	if (list_unsupported)
	{
		SkippedType[] skipped = get_skipped_types(&table, mem, &closure_set);
		defer mem::free(skipped.ptr);

		foreach (st : skipped)
		{
			io::printfn("%s: %s", st.name, st.reason);
		}
		io::printfn("Total skipped types: %d", skipped.len);

		// Lookup ReadRequest_Encoding_DefaultBinary in NodeIds.csv
		if (try nodeids_content = read_text_file(nodeids_path))
		{
			defer mem::free(nodeids_content.ptr);
			NodeIdsTable nodeids;
			parse_nodeids_csv(&nodeids, mem, nodeids_content);
			defer nodeids.free();

			if (try id = nodeids.lookup("ReadRequest_Encoding_DefaultBinary"))
			{
				io::printfn("ReadRequest_Encoding_DefaultBinary = %d (verified)", id);
			}
			else
			{
				io::printfn("ReadRequest_Encoding_DefaultBinary not found!");
			}
		}
		return 0;
	}

	// Default / --stats: print summary
	io::printfn("=== UA Types Summary ===");
	io::printfn("StructuredTypes: %d", table.struct_names.len());
	io::printfn("EnumeratedTypes: %d", table.enum_names.len());
	io::printfn("OpaqueTypes: %d", table.opaque_names.len());
	io::printfn("Total types in schema: %d", table.struct_names.len() + table.enum_names.len() + table.opaque_names.len());

	io::print("Distinct Field attributes:");
	foreach (attr : table.field_attrib_names.tvalues())
	{
		io::printf(" %s", attr);
	}
	io::printn("");

	io::printfn("Roots in %s: %d", roots_path, roots.len);
	io::printfn("Closure types: %d", closure.len);

	if (try nodeids_content = read_text_file(nodeids_path))
	{
		defer mem::free(nodeids_content.ptr);
		NodeIdsTable nodeids;
		parse_nodeids_csv(&nodeids, mem, nodeids_content);
		defer nodeids.free();
		if (try id = nodeids.lookup("ReadRequest_Encoding_DefaultBinary"))
		{
			io::printfn("ReadRequest_Encoding_DefaultBinary = %d", id);
		}
	}

	return 0;
}
