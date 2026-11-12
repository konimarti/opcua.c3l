module opcua;
import std::net;
import std::net::tcp;
import std::time;

// parse_endpoint_url and TcpTransport against a listener started inside the test (loopback only).

fn void url_parse_forms() @test
{
	EndpointUrl a = parse_endpoint_url("opc.tcp://h")!!;
	assert(a.host == "h" && a.port == 4840 && a.path == "");
	EndpointUrl b = parse_endpoint_url("opc.tcp://h:4841/p")!!;
	assert(b.host == "h" && b.port == 4841 && b.path == "/p");
	EndpointUrl c = parse_endpoint_url("opc.tcp://[::1]:4840")!!;
	assert(c.host == "::1" && c.port == 4840);
	EndpointUrl d = parse_endpoint_url("opc.tcp://[fe80::1]/x/y")!!;
	assert(d.host == "fe80::1" && d.port == 4840 && d.path == "/x/y");
	EndpointUrl e = parse_endpoint_url("opc.tcp://127.0.0.1:65535")!!;
	assert(e.port == 65535 && e.host == "127.0.0.1");
	EndpointUrl f = parse_endpoint_url("opc.tcp://host.example:1")!!;
	assert(f.port == 1);
}

fn void url_parse_errors() @test
{
	String[16] bad = {
		"http://h", "opc.tcp://", "opc.tcp://:4840", "opc.tcp://h:0", "opc.tcp://h:70000", "opc.tcp://h:65536", "opc.tcp://h:",
		"opc.tcp://h:12a", "opc.tcp://[::1", "opc.tcp://[]:1", "opc.tcp://[::1]x", "opc.tcp://[::1]:", "OPC.TCP://h", "h:4840", "", "opc.tcp:/h",
	};
	foreach (u : bad) assert(@fails(parse_endpoint_url(u), URL_INVALID), "an invalid URL is accepted");
	DString long_url = dstring::temp();
	long_url.append("opc.tcp://");
	for (int i = 0; i < 4087; i++) long_url.append("a");
	assert(long_url.len() == 4097);
	assert(@fails(parse_endpoint_url(long_url.str_view()), URL_INVALID));          // 4097 bytes
	DString ok = dstring::temp();
	ok.append("opc.tcp://");
	for (int i = 0; i < 4086; i++) ok.append("a");
	assert(parse_endpoint_url(ok.str_view())!!.port == 4840);                       // 4096 bytes
}

fn void transport_echo_and_timeouts() @test
{
	TcpServerSocket server = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)server.close();
	ushort port = server.local_port()!!;
	TcpTransport client = tcp_connect("127.0.0.1", port)!!;
	Transport t = &client;
	defer (void)t.close();
	TcpSocket conn = tcp::accept(&server)!!;
	defer (void)conn.close();

	t.write("hello", time::sec(2))!!;
	char[16] buf;
	sz n = conn.read(&buf)!!;
	assert((String)buf[:n] == "hello");
	conn.write("HELLO world")!!;
	char[4] small;
	usz first = t.read(&small, time::sec(2))!!;
	assert(first >= 1 && first <= 4);
	char[32] rest;
	String got = (String)small[:first];
	DString all = dstring::temp();
	all.append(got);
	while (all.len() < 11) all.append((String)rest[:t.read(&rest, time::sec(2))!!]);
	assert(all.str_view() == "HELLO world");

	assert(@fails(t.read(&buf, time::ms(50)), TIMEOUT), "no data: the read times out");
	assert(@fails(t.read(&buf, time::DURATION_ZERO), TIMEOUT));

	(void)conn.close();                                                                // the peer closes
	assert(@fails(t.read(&buf, time::sec(2)), CLOSED));
	(void)t.close();
	(void)t.close();                                                                   // idempotent
	assert(@fails(t.read(&buf, time::ms(10)), CLOSED));
	assert(@fails(t.write("x", time::ms(10)), CLOSED));
}

fn void transport_large_write() @test
{
	TcpServerSocket server = tcp::listen("127.0.0.1", 0, 4, REUSEADDR)!!;
	defer (void)server.close();
	ushort port = server.local_port()!!;
	TcpTransport client = tcp_connect("127.0.0.1", port)!!;
	Transport t = &client;
	defer (void)t.close();
	TcpSocket conn = tcp::accept(&server)!!;
	defer (void)conn.close();
	char[] data = alloc::alloc_array(tmem, char, 20000);
	foreach (i, &c : data) *c = (char)i;
	t.write(data, time::sec(2))!!;                                                     // fits the socket buffers: no reader needed
	sz total = 0;
	char[4096] buf;
	while (total < data.len)
	{
		sz n = conn.read(&buf)!!;
		for (sz i = 0; i < n; i++) assert(buf[i] == (char)(total + i));
		total += n;
	}
	assert(total == 20000);
}

fn void transport_connect_refused() @test
{
	TcpServerSocket server = tcp::listen("127.0.0.1", 0, 1, REUSEADDR)!!;
	ushort port = server.local_port()!!;
	(void)server.close();
	assert(!@ok(tcp_connect("127.0.0.1", port, time::sec(2))), "nothing listens on the port any more");
}

fn void clock_is_monotonic() @test
{
	Now a = clock_now();
	Now b = clock_now();
	assert(b.mono_ms >= a.mono_ms && (long)b.utc > 0);
}
