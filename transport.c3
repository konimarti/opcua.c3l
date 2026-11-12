module opcua;
import std::time;
import std::time::clock;
import std::net;
import std::net::tcp;
import std::core::env;

// The Transport interface: the shape is identical in all five libraries, each library has its own copy and its own faultdef
// with the same names TIMEOUT and CLOSED. A TlsTransport or a test double is passed in through an explicit interface cast:
//     TcpTransport tcp = tcp_connect("host", 4840)!;
//     Transport t = &tcp;
interface Transport
{
	// Reads 1..buf.len bytes. Waits at most `timeout`. Faults: TIMEOUT, CLOSED (peer EOF; the adapter then calls
	// Machine.transport_closed, which decides between TRANSPORT_TRUNCATED and CLOSED).
	fn usz? read(char[] buf, Duration timeout);
	// Writes all of data or faults (TIMEOUT, CLOSED). A chunk is handed over in one call.
	fn void? write(char[] data, Duration timeout);
	// Idempotent.
	fn void? close();
}

// The only place that deals with sockets and their timeouts: a poll based wait in front of every read and write.
// TCP_NODELAY is not exposed by std::net (SocketOption has no such member), so it is not set: a chunk is written with
// one send call, which is what avoids the small-write stalls the option guards against.
struct TcpTransport (Transport)
{
	TcpSocket socket;
	bool open;
}

fn TcpTransport? tcp_connect(String host, int port, Duration connect_timeout = time::sec(5))
{
	TcpSocket s = tcp::connect(host, port, connect_timeout)!;
	return { .socket = s, .open = true };
}

// Waits until the socket is ready for `events` or the timeout has passed. A timeout of zero or less only looks once.
fn void? wait_socket(TcpSocket* socket, PollSubscribe events, Duration timeout) @private
{
	long ms = timeout.to_ms();
	if (ms < 0) ms = 0;
	Clock start = clock::now();
	// poll can be interrupted by a signal and then reports an error although the connection is fine: look again (with
	// the time that is left) a few times before giving up
	for (int attempt = 0; attempt < 4; attempt++)
	{
		long left = ms - (long)start.to_now() / 1_000_000;
		if (left < 0) left = 0;
		Poll[1] p = { { socket.sock, events, {} } };
		ulong? ready = net::poll_ms(&p, left);
		if (try n = ready)
		{
			if (n == 0) return TIMEOUT~;
			return;
		}
	}
	return CLOSED~;
}

fn usz? TcpTransport.read(&self, char[] buf, Duration timeout) @dynamic
{
	if (!self.open) return CLOSED~;
	if (buf.len == 0) return 0;
	if (catch err = wait_socket(&self.socket, PollSubscribe.READ, timeout))
	{
		if (err == TIMEOUT) return TIMEOUT~;
		return CLOSED~;
	}
	sz? n = self.socket.read(buf);
	if (catch err = n) return CLOSED~;
	if (n == 0) return CLOSED~;                  // orderly shutdown of the peer
	return (usz)n;
}

fn void? TcpTransport.write(&self, char[] data, Duration timeout) @dynamic
{
	if (!self.open) return CLOSED~;
	sz done = 0;
	Clock start = clock::now();
	long total_ms = timeout.to_ms();
	while (done < data.len)
	{
		// one deadline for the whole write, not one per partial send
		long left = total_ms - (long)start.to_now() / 1_000_000;
		if (catch err = wait_socket(&self.socket, PollSubscribe.WRITE, time::ms(left < 0 ? 0 : left)))
		{
			if (err == TIMEOUT) return TIMEOUT~;
			return CLOSED~;
		}
		sz? n = self.socket.write(data[done..]);
		if (catch err = n) return CLOSED~;
		if (n <= 0) return CLOSED~;
		done += n;
	}
}

fn void? TcpTransport.close(&self) @dynamic
{
	if (!self.open) return;
	self.open = false;
	(void)self.socket.close();
}

// ---------- opc.tcp://host[:port][/path] ----------
struct EndpointUrl
{
	String host;
	int port;          // default 4840
	String path;
}

// The scheme is opc.tcp, an IPv6 host is written [::1], the port is 1..65535 (default 4840), the whole URL at most 4096 bytes.
// The result points into `url`.
fn EndpointUrl? parse_endpoint_url(String url)
{
	if (url.len > MAX_ENDPOINT_URL) return URL_INVALID~;
	String scheme = "opc.tcp://";
	if (url.len <= scheme.len || url[:scheme.len] != scheme) return URL_INVALID~;
	String rest = url[scheme.len..];
	foreach (c : rest)
	{
		if (c <= ' ' || c == 0x7F) return URL_INVALID~;          // blanks and control characters
	}
	EndpointUrl r = { .port = 4840 };
	sz end = 0;
	while (end < rest.len && rest[end] != '/') end++;
	String authority = rest[:end];
	foreach (c : authority)
	{
		if (c == '@') return URL_INVALID~;                        // no user info in an endpoint URL
	}
	r.path = rest[end..];
	if (authority.len == 0) return URL_INVALID~;
	String port_text;
	if (authority[0] == '[')
	{
		sz close = 0;
		while (close < authority.len && authority[close] != ']') close++;
		if (close >= authority.len || close == 1) return URL_INVALID~;
		r.host = authority[1:close - 1];
		String after = authority[close + 1..];
		if (after.len > 0)
		{
			if (after[0] != ':') return URL_INVALID~;
			port_text = after[1..];
			if (port_text.len == 0) return URL_INVALID~;
		}
	}
	else
	{
		sz colon = 0;
		while (colon < authority.len && authority[colon] != ':') colon++;
		r.host = authority[:colon];
		if (colon < authority.len)
		{
			port_text = authority[colon + 1..];
			if (port_text.len == 0) return URL_INVALID~;
		}
	}
	if (r.host.len == 0) return URL_INVALID~;
	if (port_text.len > 0)
	{
		if (port_text.len > 5) return URL_INVALID~;
		int p = 0;
		foreach (c : port_text)
		{
			if (c < '0' || c > '9') return URL_INVALID~;
			p = p * 10 + (int)(c - '0');
		}
		if (p < 1 || p > 65535) return URL_INVALID~;
		r.port = p;
	}
	return r;
}

// The adapter's clock: monotonic milliseconds and the wall clock as an OPC UA DateTime.
fn Now clock_now()
{
	long mono = (long)clock::now() / 1_000_000;
	long unix_ms = (long)time::now() / 1000;
	return { .mono_ms = (ulong)mono, .utc = datetime_from_unix_ms(unix_ms) };
}

// The library version: it is written in project.json only.
fn String version() => env::PROJECT_VERSION;
