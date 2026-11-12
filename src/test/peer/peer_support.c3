module opcua;
import std::io;
import std::io::file;
import std::os::env;
import std::time;

// Peer parameters. c3_test cannot pass environment variables, so they come from the environment or, when a key is not set,
// from the file peers/peer.env (KEY=value per line; path overridable with OPCUA_PEER_ENV; relative to the working directory of
// the test run, i.e. the repository root). Without a URL the peer tests print SKIP and pass.

struct PeerConfig
{
	bool configured;
	String url;
	String user;
	String password;
	String node_int32;
	String node_double;
	String node_string;
	String node_array;
	String method_object;
	String method;
	String method_kind;      // "add" (two Int32 in, their sum out; the default) or "string" (one String in, a String out)
}

fn String peer_file_value(String text, String key)
{
	foreach (line : text.tsplit("\n"))
	{
		String l = line.trim();
		if (l.len == 0 || l[0] == '#') continue;
		if (try eq = l.index_of("="))
		{
			if (l[:eq].trim() == key) return l[eq + 1..].trim();
		}
	}
	return "";
}

fn String peer_value(String file_text, String key)
{
	String? v = env::tget_var(key);
	if (try x = v)
	{
		if (x.len > 0) return x;
	}
	return peer_file_value(file_text, key);
}

fn PeerConfig peer_config()
{
	String path = env::tget_var("OPCUA_PEER_ENV") ?? "peers/peer.env";
	String text = "";
	char[]? bytes = file::load_temp(path);
	if (try b = bytes) text = (String)b;
	PeerConfig c;
	c.url = peer_value(text, "OPCUA_PEER_URL");
	c.user = peer_value(text, "OPCUA_USER");
	c.password = peer_value(text, "OPCUA_PASSWORD");
	c.node_int32 = peer_value(text, "OPCUA_NODE_INT32");
	c.node_double = peer_value(text, "OPCUA_NODE_DOUBLE");
	c.node_string = peer_value(text, "OPCUA_NODE_STRING");
	c.node_array = peer_value(text, "OPCUA_NODE_ARRAY");
	c.method_object = peer_value(text, "OPCUA_NODE_METHOD_OBJECT");
	c.method = peer_value(text, "OPCUA_NODE_METHOD");
	c.method_kind = peer_value(text, "OPCUA_METHOD_KIND");
	c.configured = c.url.len > 0;
	return c;
}

// true (after printing the skip line) when no peer is configured: `if (peer_skip(&pc)) return;`
fn bool peer_skip(PeerConfig* pc)
{
	if (pc.configured) return false;
	io::printn("SKIP: no peer configured");
	return true;
}

fn NodeId peer_node(String text) => parse_nodeid(text, tmem)!!;

// A connection to the peer: the transport and the client live and die together.
struct PeerConn
{
	TcpTransport tcp;
	Client* client;
}

fn PeerConn*? peer_connect(PeerConfig* pc, Config config)
{
	EndpointUrl u = parse_endpoint_url(pc.url)!;
	PeerConn* c = alloc::new_try(mem, PeerConn)!;
	c.tcp = tcp_connect(u.host, u.port)!;
	Transport t = &c.tcp;
	c.client = client_connect(mem, t, pc.url, config, (env::tget_var("OPCUA_VERBOSE") ?? "").len > 0)!;
	return c;
}

fn void PeerConn.drop(&self)
{
	(void)self.client.close();
	self.client.free();
	(void)self.tcp.close();
	mem::free(self);
}

fn Config peer_default_config()
{
	Config c = default_config();
	c.request_timeout_ms = 5000;
	return c;
}

// Prints an observation and appends it to peers/observed.log (git-ignored), because a passing test shows no output.
fn void peer_note(String text)
{
	io::printn(text);
	File? f = file::open("peers/observed.log", "a");
	if (catch err = f) return;
	(void)f.write(text);
	(void)f.write("\n");
	(void)f.close();
}
