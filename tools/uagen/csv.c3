module uagen;
import std::collections::list;
import std::collections::map;

struct NodeIdsTable
{
	Allocator allocator;
	HashMap{String, uint} ids;
}

fn void NodeIdsTable.init(&self, Allocator allocator)
{
	self.allocator = allocator;
	self.ids.init(allocator);
}

fn void NodeIdsTable.free(&self)
{
	self.ids.free();
}

fn uint? NodeIdsTable.lookup(&self, String name)
{
	return self.ids.get(name);
}

fn void parse_nodeids_csv(NodeIdsTable* table, Allocator allocator, String content)
{
	table.init(allocator);

	foreach (raw_line : content.tsplit("\n"))
	{
		String line = raw_line.trim();
		if (line.len == 0 || line[0] == '#') continue;

		String[] parts = line.split(tmem, ",", 3);
		if (parts.len >= 2)
		{
			String name = parts[0].trim();
			String id_str = parts[1].trim();
			if (try id = string::to_integer{uint}(id_str))
			{
				table.ids.set(name, id);
			}
		}
	}
}

struct StatusCodeEntry
{
	String name;
	uint code;
	String description;
}

struct StatusCodeTable
{
	Allocator allocator;
	List{StatusCodeEntry} entries;
	HashMap{String, uint} by_name;
}

fn void StatusCodeTable.init(&self, Allocator allocator)
{
	self.allocator = allocator;
	self.entries.init(allocator);
	self.by_name.init(allocator);
}

fn void StatusCodeTable.free(&self)
{
	self.entries.free();
	self.by_name.free();
}

fn void parse_statuscode_csv(StatusCodeTable* table, Allocator allocator, String content)
{
	table.init(allocator);

	foreach (raw_line : content.tsplit("\n"))
	{
		String line = raw_line.trim();
		if (line.len == 0 || line[0] == '#') continue;

		String[] parts = line.split(tmem, ",", 3);
		if (parts.len >= 2)
		{
			String name = parts[0].trim();
			String code_str = parts[1].trim();
			String desc = parts.len >= 3 ? parts[2].trim() : "";
			// Strip quotes if present
			if (desc.len >= 2 && desc[0] == '"' && desc[desc.len - 1] == '"')
			{
				desc = desc[1..desc.len - 2];
			}
			if (try code = string::to_integer{uint}(code_str))
			{
				StatusCodeEntry entry = { .name = name, .code = code, .description = desc };
				table.entries.push(entry);
				table.by_name.set(name, code);
			}
		}
	}
}
