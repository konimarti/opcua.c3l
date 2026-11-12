module opcua;
import std::core::env;

// In the library's own test build the library is the top-level project, so env::PROJECT_VERSION is the version of project.json.
fn void version_matches_project_json() @test
{
	assert(opcua::VERSION == env::PROJECT_VERSION);
}
