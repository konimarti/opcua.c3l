module opcua;

fn void version_comes_from_project_json() @test
{
	assert(version() == "0.1.0");
}
