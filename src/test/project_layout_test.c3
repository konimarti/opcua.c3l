module opcua;
import std::io::file;

// The static library must contain the library only: the tool in tools/ and the tests belong to the test sources, or the
// archive would export `main` and the whole generator. tools/check-lib-symbols.sh checks the built archive itself.

fn String section(String text, String key)
{
	String needle = string::tformat("\"%s\": [", key);
	if (try start = text.index_of(needle))
	{
		String rest = text[start + needle.len..];
		if (try end = rest.index_of("]")) return rest[:end];
	}
	return "";
}

fn void layout_library_sources_exclude_tools_and_tests() @test
{
	char[] bytes = file::load(mem, "project.json")!!;
	defer mem::free(bytes.ptr);
	String json = (String)bytes;
	String top = json[:json.index_of("\"targets\"")!!];
	String lib = section(top, "sources");
	assert(lib.contains("./*"), "the library sources are the root files");
	assert(!lib.contains("tools") && !lib.contains("src/test"), "no tool and no test code in the library");
	String tests = section(top, "test-sources");
	assert(tests.contains("src/test/**") && tests.contains("tools/uagen/**"), "the tests of the library and of the tool still run");
}
