module uagen;
import std::io;
import std::io::file;

struct Generated
{
	String path;
	String content;
}

// Builds the three generated files in memory.
fn Generated[3]? build_outputs(TypeTable* table, String[] closure, String source_text, NodeIdsTable* ids, StatusCodeTable* statuses)
{
	DString types_out;
	types_out.init(tmem);
	emit_types(table, closure, source_text, &types_out)!;
	DString codec_out;
	codec_out.init(tmem);
	emit_codec(table, closure, source_text, &codec_out)!;
	DString ids_out;
	ids_out.init(tmem);
	emit_ids(table, closure, ids, statuses, source_text, &ids_out)!;
	return {
		{ "gen_types.c3", types_out.str_view() },
		{ "gen_codec.c3", codec_out.str_view() },
		{ "gen_ids.c3", ids_out.str_view() },
	};
}

// First line where two texts differ, 1 based; 0 when equal.
fn sz first_difference(String a, String b)
{
	sz line = 1;
	sz n = a.len < b.len ? a.len : b.len;
	for (sz i = 0; i < n; i++)
	{
		if (a[i] != b[i]) return line;
		if (a[i] == '\n') line++;
	}
	return a.len == b.len ? 0 : line;
}

fn String line_at(String text, sz number)
{
	sz line = 1;
	sz start = 0;
	for (sz i = 0; i < text.len; i++)
	{
		if (line == number && text[i] == '\n') return text[start:i - start];
		if (text[i] == '\n')
		{
			line++;
			if (line == number) start = i + 1;
		}
	}
	return line == number ? text[start..] : "<end of file>";
}

// --generate writes the files, --check compares them with the committed ones. Returns the exit code.
fn int run_generate(Generated[3] outputs, bool check)
{
	int exit_code = 0;
	foreach (g : outputs)
	{
		if (!check)
		{
			if (catch err = file::save(g.path, (char[])g.content))
			{
				io::printfn("Error: cannot write %s", g.path);
				return 1;
			}
			io::printfn("wrote %s", g.path);
			continue;
		}
		String? current = read_text_file(g.path);
		if (catch err = current)
		{
			io::printfn("%s: missing", g.path);
			exit_code = 1;
			continue;
		}
		defer mem::free(current.ptr);
		sz at = first_difference(current, g.content);
		if (at != 0)
		{
			io::printfn("%s differs at line %d", g.path, at);
			io::printfn("  committed: %s", line_at(current, at));
			io::printfn("  generated: %s", line_at(g.content, at));
			exit_code = 1;
		}
	}
	if (check && exit_code == 0) io::printn("up to date");
	return exit_code;
}
