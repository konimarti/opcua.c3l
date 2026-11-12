module opcua;                // the tool is part of the library module so that it can use every name unqualified
import std::io;
import std::os::env;
import std::time;

// uatool endpoints|browse|read|write: a small command line client (exit codes: 0 ok, 1 error, 2 usage or refused).

struct Options
{
	String command;
	String url;
	String[] args;           // the positional arguments after the URL
	bool allow_write;
	bool allow_cleartext_password;
	bool verbose;
	String user;
	String password;
	String node;
	String attr;
	int depth;
}

fn int usage()
{
	io::eprintn("usage: uatool endpoints <opc.tcp://host:port>");
	io::eprintn("       uatool browse    <url> [--node ns=0;i=85] [--depth 1]");
	io::eprintn("       uatool read      <url> <nodeid>... [--attr value|browsename|displayname|datatype]");
	io::eprintn("       uatool write     <url> <nodeid> <type:value> --allow-write [--user U --password P --allow-cleartext-password]");
	io::eprintn("options: --verbose (redacted trace on stderr), --user U --password P --allow-cleartext-password");
	io::eprintn("         --password-env NAME reads the password from that environment variable (keeps it out of the process list)");
	io::eprintn("write types: i32, u32, f64, bool, str");
	return 2;
}

fn bool parse_args(String[] argv, Options* o)
{
	o.depth = 1;
	o.node = "i=85";
	o.attr = "value";
	String[] positional = alloc::alloc_array(tmem, String, argv.len);
	sz n = 0;
	for (sz i = 1; i < argv.len; i++)
	{
		String a = argv[i];
		if (a == "--allow-write")
		{
			o.allow_write = true;
		}
		else if (a == "--allow-cleartext-password")
		{
			o.allow_cleartext_password = true;
		}
		else if (a == "--verbose")
		{
			o.verbose = true;
		}
		else if (a == "--user" || a == "--password" || a == "--password-env" || a == "--node" || a == "--attr" || a == "--depth")
		{
			if (i + 1 >= argv.len) return false;
			String v = argv[++i];
			if (a == "--user") o.user = v;
			if (a == "--password")
			{
				io::eprintn("warning: --password is visible in the process list and the shell history; prefer --password-env NAME");
				o.password = v;
			}
			if (a == "--password-env")
			{
				String? pw = env::tget_var(v);
				if (catch pw)
				{
					io::eprintfn("environment variable %s is not set", v);
					return false;
				}
				o.password = pw;
			}
			if (a == "--node") o.node = v;
			if (a == "--attr") o.attr = v;
			if (a == "--depth")
			{
				int? d = string::to_integer{int}(v);
				if (catch d) return false;
				o.depth = d < 1 ? 1 : d;
			}
		}
		else if (a.len > 1 && a[0] == '-' && a[1] == '-')
		{
			return false;
		}
		else
		{
			positional[n++] = a;
		}
	}
	if (n < 2) return false;
	o.command = positional[0];
	o.url = positional[1];
	o.args = positional[2:n - 2];
	return true;
}

fn String mode_name(MessageSecurityMode m)
{
	switch (m)
	{
		case MessageSecurityMode.NONE: return "None";
		case MessageSecurityMode.SIGN: return "Sign";
		case MessageSecurityMode.SIGN_AND_ENCRYPT: return "SignAndEncrypt";
		default: return "Invalid";
	}
}

fn String token_name(UserTokenType t)
{
	switch (t)
	{
		case UserTokenType.ANONYMOUS: return "anonymous";
		case UserTokenType.USER_NAME: return "username";
		case UserTokenType.CERTIFICATE: return "certificate";
		default: return "issued";
	}
}

fn String value_text(Variant v)
{
	if (v.is_array) return string::tformat("<array of %d>", v.count());
	switch (v.type)
	{
		case EMPTY: return "<empty>";
		case BOOLEAN: return v.scalar.b ? "true" : "false";
		case SBYTE: return string::tformat("%d", v.scalar.i8);
		case BYTE: return string::tformat("%d", v.scalar.u8);
		case INT16: return string::tformat("%d", v.scalar.i16);
		case UINT16: return string::tformat("%d", v.scalar.u16);
		case INT32: return string::tformat("%d", v.scalar.i32);
		case UINT32: return string::tformat("%d", v.scalar.u32);
		case INT64: return string::tformat("%d", v.scalar.i64);
		case UINT64: return string::tformat("%d", v.scalar.u64);
		case FLOAT: return string::tformat("%s", v.scalar.f32);
		case DOUBLE: return string::tformat("%s", v.scalar.f64);
		case STRING: return v.scalar.str;
		case STATUSCODE: return status_name(v.scalar.sc);
		default: return "<value>";
	}
}

fn String class_name(NodeClass c)
{
	switch (c)
	{
		case NodeClass.OBJECT: return "Object";
		case NodeClass.VARIABLE: return "Variable";
		case NodeClass.METHOD: return "Method";
		case NodeClass.OBJECT_TYPE: return "ObjectType";
		case NodeClass.VARIABLE_TYPE: return "VariableType";
		case NodeClass.REFERENCE_TYPE: return "ReferenceType";
		case NodeClass.DATA_TYPE: return "DataType";
		case NodeClass.VIEW: return "View";
		default: return "Unspecified";
	}
}

fn uint attribute_of(String name)
{
	if (name == "browsename") return ATTRIBUTE_BROWSE_NAME;
	if (name == "displayname") return ATTRIBUTE_DISPLAY_NAME;
	if (name == "datatype") return ATTRIBUTE_DATA_TYPE;
	return ATTRIBUTE_VALUE;
}

fn Variant? parse_value(String text, Allocator a)
{
	sz colon = 0;
	while (colon < text.len && text[colon] != ':') colon++;
	if (colon >= text.len) return UNKNOWN_TYPE~;
	String type = text[:colon];
	String value = text[colon + 1..];
	if (type == "i32") return variant_i32(string::to_integer{int}(value)!);
	if (type == "u32") return variant_u32(string::to_integer{uint}(value)!);
	if (type == "f64") return variant_f64(value.to_double()!);
	if (type == "bool") return variant_bool(value == "true" || value == "1");
	if (type == "str") return variant_string(value.copy(a));
	return UNKNOWN_TYPE~;
}

fn Config make_config(Options* o)
{
	Config c = default_config();
	c.allow_write = o.allow_write;
	c.allow_cleartext_password = o.allow_cleartext_password;
	return c;
}

struct Conn
{
	TcpTransport tcp;
	Client* client;
}

fn void? connect(Options* o, Conn* c, bool with_session)
{
	EndpointUrl u = parse_endpoint_url(o.url)!;
	c.tcp = tcp_connect(u.host, u.port)!;
	Transport t = &c.tcp;
	c.client = client_connect(mem, t, o.url, make_config(o), o.verbose)!;
	if (with_session)
	{
		Identity id = o.user.len > 0 ? identity_username(o.user, o.password) : identity_anonymous();
		c.client.open_session(id)!;
	}
}

fn void Conn.drop(&self)
{
	if (self.client != null)
	{
		(void)self.client.close();
		self.client.free();
	}
	(void)self.tcp.close();
}

fn int report(String what, fault f, Client* c)
{
	if (f == SERVICE_FAULT && c != null)
	{
		io::eprintfn("%s: %s (status %s)", what, f, status_name(c.last_status));
	}
	else
	{
		io::eprintfn("%s: %s", what, f);
	}
	return 1;
}

fn int cmd_endpoints(Options* o)
{
	Conn c;
	if (catch err = connect(o, &c, false)) return report("connect", err, c.client);
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	EndpointDescription[]? eps = c.client.get_endpoints(&arena);
	if (catch err = eps) return report("endpoints", err, c.client);
	foreach (ep : eps)
	{
		DString tokens = dstring::temp();
		foreach (i, p : ep.user_identity_tokens)
		{
			if (i > 0) tokens.append(",");
			tokens.append(token_name(p.token_type));
		}
		io::printfn("endpoint %s mode=%s policy=%s tokens=%s", ep.endpoint_url, mode_name(ep.security_mode), ep.security_policy_uri, tokens.str_view());
	}
	return 0;
}

fn int cmd_read(Options* o)
{
	if (o.args.len == 0) return usage();
	Conn c;
	if (catch err = connect(o, &c, true)) return report("connect", err, c.client);
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	uint attr = attribute_of(o.attr);
	ReadValueId[] nodes = alloc::alloc_array(tmem, ReadValueId, o.args.len);
	foreach (i, a : o.args)
	{
		NodeId? id = parse_nodeid(a, tmem);
		if (catch id)
		{
			io::eprintfn("bad node id: %s", a);
			return 2;
		}
		nodes[i] = { .node_id = id, .attribute_id = attr };
	}
	DataValue[]? values = c.client.read_many(&arena, nodes);
	if (catch err = values) return report("read", err, c.client);
	foreach (i, v : values)
	{
		io::printfn("%s %s %s", o.args[i], status_name(v.status), v.has_value ? value_text(v.value) : "<no value>");
	}
	return 0;
}

fn int cmd_write(Options* o)
{
	if (o.args.len != 2) return usage();
	if (!o.allow_write)
	{
		io::eprintn("write refused: pass --allow-write");
		return 2;
	}
	NodeId? id = parse_nodeid(o.args[0], tmem);
	if (catch id)
	{
		io::eprintfn("bad node id: %s", o.args[0]);
		return 2;
	}
	Variant? value = parse_value(o.args[1], tmem);
	if (catch value)
	{
		io::eprintfn("bad value: %s (use i32:7, u32:7, f64:1.5, bool:true, str:text)", o.args[1]);
		return 2;
	}
	Conn c;
	if (catch err = connect(o, &c, true)) return report("connect", err, c.client);
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	StatusCode? status = c.client.write(&arena, id, value);
	if (catch err = status) return report("write", err, c.client);
	io::printfn("%s %s", o.args[0], status_name(status));
	return status_is_good(status) ? 0 : 1;
}

fn int browse_node(Client* client, Allocator a, NodeId node, int depth, int level)
{
	BrowseResult? r = client.browse(a, node);
	if (catch err = r) return report("browse", err, client);
	foreach (ref : r.references)
	{
		DString indent = dstring::temp();
		for (int i = 0; i < level; i++) indent.append("  ");
		io::printfn("%s%s %s %s", indent.str_view(), ref.browse_name.name, nodeid_to_string(ref.node_id.id, tmem), class_name(ref.node_class));
		if (level + 1 < depth)
		{
			int rc = browse_node(client, a, ref.node_id.id, depth, level + 1);
			if (rc != 0) return rc;
		}
	}
	return 0;
}

fn int cmd_browse(Options* o)
{
	NodeId? start = parse_nodeid(o.node, tmem);
	if (catch start)
	{
		io::eprintfn("bad node id: %s", o.node);
		return 2;
	}
	Conn c;
	if (catch err = connect(o, &c, true)) return report("connect", err, c.client);
	defer c.drop();
	DynamicArenaAllocator arena;
	arena.init(mem, 8192);
	defer arena.free();
	return browse_node(c.client, &arena, start, o.depth, 0);
}

fn int main(String[] args)
{
	if (args.len == 2 && args[1] == "--version")
	{
		io::printn(VERSION);
		return 0;
	}
	Options o;
	if (!parse_args(args, &o)) return usage();
	if (o.command == "endpoints") return cmd_endpoints(&o);
	if (o.command == "browse") return cmd_browse(&o);
	if (o.command == "read") return cmd_read(&o);
	if (o.command == "write") return cmd_write(&o);
	return usage();
}
