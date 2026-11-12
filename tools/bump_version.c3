module bump_version;
import std::io;
import std::io::file;

// Sets the library version in project.json and in `const String VERSION` of the main module file. Run from the repository root:
//     c3c compile-run tools/bump_version.c3 -- 0.2.0
// Exit 1 and nothing written unless the argument is MAJOR.MINOR.PATCH and each pattern occurs exactly once.

const String PROJECT_FILE = "project.json";
const String MAIN_FILE = "types.c3";
const String PROJECT_PATTERN = "\"version\": \"";
const String MAIN_PATTERN = "const String VERSION = \"";

fn bool is_version(String v)
{
	int parts = 0;
	int digits = 0;
	foreach (c : v)
	{
		if (c >= '0' && c <= '9')
		{
			digits++;
		}
		else if (c == '.' && digits > 0)
		{
			parts++;
			digits = 0;
		}
		else
		{
			return false;
		}
	}
	return parts == 2 && digits > 0;
}

fn int occurrences(String text, String pattern)
{
	int n = 0;
	String rest = text;
	while (try at = rest.index_of(pattern))
	{
		n++;
		rest = rest[at + pattern.len..];
	}
	return n;
}

// The text with the quoted value that follows `pattern` replaced by `version`.
fn String replace_value(String text, String pattern, String version)
{
	sz at = text.index_of(pattern)!!;
	sz start = at + pattern.len;
	sz end = start;
	while (end < text.len && text[end] != '"') end++;
	return string::tformat("%s%s%s", text[:start], version, text[end..]);
}

// The line of `text` that contains `pattern`.
fn String line_of(String text, String pattern)
{
	sz at = text.index_of(pattern)!!;
	sz start = at;
	while (start > 0 && text[start - 1] != '\n') start--;
	sz end = at;
	while (end < text.len && text[end] != '\n') end++;
	return text[start:end - start];
}

fn int main(String[] args)
{
	if (args.len != 2 || !is_version(args[1]))
	{
		io::eprintn("usage: bump_version MAJOR.MINOR.PATCH   (run from the repository root)");
		return 1;
	}
	String version = args[1];
	char[]? project = file::load_temp(PROJECT_FILE);
	char[]? main_file = file::load_temp(MAIN_FILE);
	if (catch project)
	{
		io::eprintfn("cannot read %s", PROJECT_FILE);
		return 1;
	}
	if (catch main_file)
	{
		io::eprintfn("cannot read %s", MAIN_FILE);
		return 1;
	}
	String project_text = (String)project;
	String main_text = (String)main_file;
	if (occurrences(project_text, PROJECT_PATTERN) != 1)
	{
		io::eprintfn("%s: the version line must occur exactly once", PROJECT_FILE);
		return 1;
	}
	if (occurrences(main_text, MAIN_PATTERN) != 1)
	{
		io::eprintfn("%s: the VERSION line must occur exactly once", MAIN_FILE);
		return 1;
	}
	String new_project = replace_value(project_text, PROJECT_PATTERN, version);
	String new_main = replace_value(main_text, MAIN_PATTERN, version);
	if (catch err = file::save(PROJECT_FILE, (char[])new_project))
	{
		io::eprintfn("cannot write %s", PROJECT_FILE);
		return 1;
	}
	if (catch err = file::save(MAIN_FILE, (char[])new_main))
	{
		io::eprintfn("cannot write %s (%s was already changed)", MAIN_FILE, PROJECT_FILE);
		return 1;
	}
	io::printfn("%s: %s", PROJECT_FILE, line_of(new_project, PROJECT_PATTERN).trim());
	io::printfn("%s: %s", MAIN_FILE, line_of(new_main, MAIN_PATTERN).trim());
	return 0;
}
