module opcua;
import std::io::file;
import uagen;

// Generated structure codecs (gen_types.c3, gen_codec.c3, gen_ids.c3). Vectors EO4, M71, M72, M80 and the hand-laid-out
// ReadRequest of 10000-4 5.10.2.

fn char[] enc_read_request(ReadRequest v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_read_request(v)!!; return b.bytes(); }
fn char[] enc_browse_request(BrowseRequest v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_browse_request(v)!!; return b.bytes(); }
fn char[] enc_call_request(CallRequest v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_call_request(v)!!; return b.bytes(); }
fn char[] enc_session_response(CreateSessionResponse v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_create_session_response(v)!!; return b.bytes(); }
fn char[] enc_reference(ReferenceDescription v) { ByteBuf b; b.init(tmem); Encoder e = encoder(&b); e.put_reference_description(v)!!; return b.bytes(); }

fn RequestHeader test_header() => { .request_handle = 7, .timeout_hint = 5000, .timestamp = (UaDateTime)116444736000000000 };

// ---------- roundtrip ----------
fn void roundtrip_read_request() @test
{
	ReadValueId[2] nodes = { { .node_id = nodeid_num(0, 2259), .attribute_id = 13 }, { .node_id = nodeid_str(2, "Hot"), .attribute_id = 1, .index_range = "1:2" } };
	ReadRequest r = { .request_header = test_header(), .max_age = 250.5, .timestamps_to_return = TimestampsToReturn.BOTH, .nodes_to_read = &nodes };
	char[] bytes = enc_read_request(r);
	Decoder d = decoder(bytes, tmem);
	ReadRequest back = d.get_read_request()!!;
	assert(d.remaining() == 0 && d.depth == 0);
	assert(back.request_header.request_handle == 7 && back.max_age == 250.5 && back.timestamps_to_return == TimestampsToReturn.BOTH);
	assert(back.nodes_to_read.len == 2 && nodeid_equals(back.nodes_to_read[1].node_id, nodeid_str(2, "Hot")) && back.nodes_to_read[1].index_range == "1:2");
	assert(is_null(back.nodes_to_read[0].index_range));
	assert(enc_read_request(back) == bytes);
}

fn void roundtrip_browse_request() @test
{
	BrowseDescription[1] nodes = { { .node_id = nodeid_num(0, 85), .browse_direction = BrowseDirection.FORWARD, .reference_type_id = nodeid_num(0, 33), .include_subtypes = true, .node_class_mask = 0xFF, .result_mask = 63 } };
	BrowseRequest r = { .request_header = test_header(), .requested_max_references_per_node = 100, .nodes_to_browse = &nodes };
	char[] bytes = enc_browse_request(r);
	Decoder d = decoder(bytes, tmem);
	BrowseRequest back = d.get_browse_request()!!;
	assert(d.remaining() == 0);
	assert(back.requested_max_references_per_node == 100 && back.nodes_to_browse.len == 1 && back.nodes_to_browse[0].include_subtypes);
	assert(back.nodes_to_browse[0].browse_direction == BrowseDirection.FORWARD && back.nodes_to_browse[0].result_mask == 63);
	assert(enc_browse_request(back) == bytes);
}

fn void roundtrip_create_session_response() @test
{
	UserTokenPolicy[2] policies = { { .policy_id = "anon", .token_type = UserTokenType.ANONYMOUS }, { .policy_id = "user", .token_type = UserTokenType.USER_NAME, .security_policy_uri = "http://x" } };
	EndpointDescription[2] endpoints;
	endpoints[0] = { .endpoint_url = "opc.tcp://h:4840", .security_mode = MessageSecurityMode.NONE, .security_policy_uri = POLICY_NONE, .user_identity_tokens = &policies, .security_level = 3 };
	endpoints[0].server = { .application_uri = "urn:s", .application_name = { "en", "Server" }, .application_type = ApplicationType.SERVER };
	endpoints[1] = { .endpoint_url = "opc.tcp://h:4841", .security_mode = MessageSecurityMode.SIGN_AND_ENCRYPT, .server_certificate = unhex("30 82 01") };
	CreateSessionResponse r = { .session_id = nodeid_num(1, 77), .authentication_token = nodeid_str(1, "tok"), .revised_session_timeout = 60000.0, .server_nonce = unhex("01 02 03 04"), .server_endpoints = &endpoints, .max_request_message_size = 4096 };
	r.response_header.request_handle = 3;
	char[] bytes = enc_session_response(r);
	Decoder d = decoder(bytes, tmem);
	CreateSessionResponse back = d.get_create_session_response()!!;
	assert(d.remaining() == 0 && d.depth == 0);
	assert(back.server_endpoints.len == 2 && back.server_endpoints[0].user_identity_tokens.len == 2);
	assert(back.server_endpoints[0].user_identity_tokens[1].token_type == UserTokenType.USER_NAME);
	assert(back.server_endpoints[0].server.application_name.text == "Server" && back.server_endpoints[0].server.application_type == ApplicationType.SERVER);
	assert(back.server_endpoints[1].security_mode == MessageSecurityMode.SIGN_AND_ENCRYPT && back.server_endpoints[1].server_certificate == unhex("30 82 01"));
	assert(back.revised_session_timeout == 60000.0 && back.max_request_message_size == 4096 && back.response_header.request_handle == 3);
	assert(enc_session_response(back) == bytes);
}

fn void roundtrip_call_request_with_variant() @test
{
	Variant[2] args = { variant_i32(5), variant_string("hi") };
	CallMethodRequest[1] calls = { { .object_id = nodeid_num(2, 100), .method_id = nodeid_num(2, 101), .input_arguments = &args } };
	CallRequest r = { .request_header = test_header(), .methods_to_call = &calls };
	char[] bytes = enc_call_request(r);
	Decoder d = decoder(bytes, tmem);
	CallRequest back = d.get_call_request()!!;
	assert(d.remaining() == 0);
	assert(back.methods_to_call.len == 1 && back.methods_to_call[0].input_arguments.len == 2);
	assert(back.methods_to_call[0].input_arguments[0].scalar.i32 == 5 && back.methods_to_call[0].input_arguments[1].scalar.str == "hi");
	assert(enc_call_request(back) == bytes);
}

fn void roundtrip_every_prefix_is_truncated() @test
{
	ReadValueId[1] nodes = { { .node_id = nodeid_num(0, 2259), .attribute_id = 13 } };
	ReadRequest r = { .request_header = test_header(), .nodes_to_read = &nodes };
	char[] bytes = enc_read_request(r);
	for (sz at = 0; at < bytes.len; at++)
	{
		Decoder d = decoder(bytes[:at], tmem);
		assert(@fails(d.get_read_request(), TRUNCATED));
		assert(d.depth == 0);
	}
}

// ---------- readrequest_bytes ----------
fn void readrequest_bytes() @test
{
	ReadValueId[1] nodes = { { .node_id = nodeid_num(0, 2259), .attribute_id = 13 } };
	ReadRequest r = { .request_header = { .request_handle = 1, .timeout_hint = 1000 }, .max_age = 0.0, .timestamps_to_return = TimestampsToReturn.BOTH, .nodes_to_read = &nodes };
	String hex = "00 00  00 00 00 00 00 00 00 00  01 00 00 00  00 00 00 00  FF FF FF FF  E8 03 00 00  00 00 00"   // RequestHeader
		+++ "  00 00 00 00 00 00 00 00"                                                                         // MaxAge 0.0
		+++ "  02 00 00 00"                                                                                     // Both
		+++ "  01 00 00 00"                                                                                     // one node
		+++ "  01 00 D3 08  0D 00 00 00  FF FF FF FF  00 00 FF FF FF FF";                                       // i=2259, Value, IndexRange null, DataEncoding 0:null
	assert(enc_read_request(r) == unhex(hex));
	Decoder d = dec(hex);
	ReadRequest back = d.get_read_request()!!;
	assert(d.remaining() == 0 && back.timestamps_to_return == TimestampsToReturn.BOTH && back.nodes_to_read[0].attribute_id == 13);
	assert(is_null(back.nodes_to_read[0].index_range) && back.nodes_to_read[0].data_encoding.ns == 0 && is_null(back.nodes_to_read[0].data_encoding.name));
	assert(is_null(back.request_header.audit_entry_id) && !back.request_header.additional_header.encoding);
}

// ---------- encoding_ids ----------
fn void encoding_ids() @test
{
	assert(READ_REQUEST_ENCODING_ID == 631 && READ_RESPONSE_ENCODING_ID == 634);
	char[] bytes = file::load(mem, "schema/NodeIds.csv")!!;
	defer mem::free(bytes.ptr);
	NodeIdsTable ids;
	uagen::parse_nodeids_csv(&ids, mem, (String)bytes);
	defer ids.free();
	assert(ids.lookup("ReadRequest_Encoding_DefaultBinary")!! == READ_REQUEST_ENCODING_ID);
	assert(ids.lookup("ReadResponse_Encoding_DefaultBinary")!! == READ_RESPONSE_ENCODING_ID);
	assert(ids.lookup("OpenSecureChannelRequest_Encoding_DefaultBinary")!! == OPEN_SECURE_CHANNEL_REQUEST_ENCODING_ID);
	assert(ids.lookup("OpenSecureChannelResponse_Encoding_DefaultBinary")!! == OPEN_SECURE_CHANNEL_RESPONSE_ENCODING_ID);
	assert(ids.lookup("CloseSecureChannelRequest_Encoding_DefaultBinary")!! == CLOSE_SECURE_CHANNEL_REQUEST_ENCODING_ID);
	assert(ids.lookup("ServiceFault_Encoding_DefaultBinary")!! == SERVICE_FAULT_ENCODING_ID);
	assert(ids.lookup("Argument_Encoding_DefaultBinary")!! == ARGUMENT_ENCODING_ID && ARGUMENT_ENCODING_ID == 298);
	assert(ATTRIBUTE_VALUE == 13 && ATTRIBUTE_NODE_ID == 1 && ATTRIBUTE_ACCESS_LEVEL_EX == 27);
	assert(status_name((StatusCode)0) == "Good" && status_name((StatusCode)0x80340000) == "BadNodeIdUnknown");
	assert(status_name((StatusCode)0x80340001) == "BadNodeIdUnknown", "the info bits are ignored");
	assert(status_name((StatusCode)0x80AE0000) == "BadConnectionClosed" && status_name((StatusCode)0x80010000) == "BadUnexpectedError");
	assert(status_name((StatusCode)0x12340000) == "Unknown");
}

// ---------- extobj_known ----------
fn void extobj_known_argument() @test
{
	String hex = "01 00 2A 01 01 10 00 00 00 01 00 00 00 78 00 06 FF FF FF FF FF FF FF FF 00";   // EO4
	Decoder d = dec(hex);
	ExtensionObject eo = d.get_extension_object()!!;
	assert(d.remaining() == 0 && eo.encoding == 1 && eo.type_id.num == ARGUMENT_ENCODING_ID);
	Decoder body = extobj_body_decoder(&eo, tmem)!!;
	Argument a = body.get_argument()!!;
	assert(a.name == "x" && nodeid_equals(a.data_type, nodeid_num(0, 6)) && a.value_rank == -1);
	assert(is_null_array_u32(a.array_dimensions) && is_null(a.description.text) && is_null(a.description.locale));
	assert(body.remaining() == 0, "the cursor sits at the declared body end");
	Encoder sizer = encoder_sizer();
	sizer.put_argument(a)!!;
	assert(sizer.written == 16);
	// M71: the declared body is shorter than the structure
	Decoder shorter = dec("01 00 2A 01 01 04 00 00 00 01 00 00 00");
	ExtensionObject so = shorter.get_extension_object()!!;
	Decoder sb = extobj_body_decoder(&so, tmem)!!;
	assert(@fails(sb.get_argument(), TRUNCATED));
	// M72: four extra bytes inside the declared body are skipped
	Decoder longer = dec("01 00 2A 01 01 14 00 00 00 01 00 00 00 78 00 06 FF FF FF FF FF FF FF FF 00 AA AA AA AA");
	ExtensionObject lo = longer.get_extension_object()!!;
	assert(longer.remaining() == 0, "the outer cursor is at the declared end");
	Decoder lb = extobj_body_decoder(&lo, tmem)!!;
	Argument b = lb.get_argument()!!;
	assert(b.name == "x" && lb.remaining() == 4);
	// a body that is not binary is refused
	ExtensionObject xml = { .type_id = nodeid_num(0, ARGUMENT_ENCODING_ID), .encoding = 2, .body = (char[])"<a/>" };
	assert(@fails(extobj_body_decoder(&xml, tmem), BAD_ENCODING));
	ExtensionObject none;
	assert(@fails(extobj_body_decoder(&none, tmem), BAD_ENCODING));
}

fn bool is_null_array_u32(uint[] a) => a.ptr == null;

// ---------- enum_unknown ----------
fn void enum_unknown() @test
{
	// M80: NodeClass 9999 is not a member; it is accepted, kept and written back unchanged
	String hex = "00 00  01  00 00  00 00 FF FF FF FF  00  0F 27 00 00  00 00";     // NodeClass 9999
	Decoder d = dec(hex);
	ReferenceDescription r = d.get_reference_description()!!;
	assert(d.remaining() == 0);
	assert((int)r.node_class == 9999);
	assert(r.node_class != NodeClass.OBJECT);
	assert(enc_reference(r) == unhex(hex));
	ReferenceDescription known = r;
	known.node_class = NodeClass.VARIABLE;
	assert(enc_reference(known)[12:4] == unhex("02 00 00 00"));
	// negative and very large wire values survive as well
	ReferenceDescription big = r;
	big.node_class = (NodeClass)-5;
	Decoder back = decoder(enc_reference(big), tmem);
	assert((int)back.get_reference_description()!!.node_class == -5);
	// an OptionSet stays a plain integer
	BrowseDescription bd = { .node_class_mask = 0xFFFFFFFF, .result_mask = 0x80000001 };
	assert(bd.node_class_mask == 0xFFFFFFFF);
}

// ---------- keyword_escape ----------
fn void keyword_escape() @test
{
	assert(uagen::escape_name("type") == "type_" && uagen::escape_name("default") == "default_" && uagen::escape_name("name") == "name");
	assert(uagen::snake_case("ServerURI") == "server_uri" && uagen::snake_case("NodeId") == "node_id");
	assert(uagen::snake_case("UserIdentityToken") == "user_identity_token" && uagen::snake_case("Int32Value") == "int32_value");
	assert(uagen::field_name("Type") == "type_");
	char[] bytes = file::load(mem, "tools/uagen/testdata/keywords.bsd")!!;
	defer mem::free(bytes.ptr);
	TypeTable table;
	table.init(mem);
	defer table.free();
	uagen::parse_bsd(&table, (String)bytes)!!;
	String[1] closure = { "KeywordHolder" };
	DString types;
	types.init(tmem);
	uagen::emit_types(&table, &closure, "src", &types)!!;
	String t = types.str_view();
	assert(t.contains("\tint type_;") && t.contains("\tString default_;") && t.contains("\tString[] names;") && t.contains("\tString server_uri;"));
	assert(!t.contains("no_of_names"));
	DString codec;
	codec.init(tmem);
	uagen::emit_codec(&table, &closure, "src", &codec)!!;
	String c = codec.str_view();
	assert(c.contains("self.put_u32((uint)v.type_)!;") && c.contains("v.type_ = (int)self.get_u32()!;"));
	assert(c.contains("self.get_array_len(4)!"));
	assert(t.starts_with("// DO NOT EDIT"));
}

// ---------- null_defaults ----------
fn void null_defaults() @test
{
	CallRequest empty;
	char[] bytes = enc_call_request(empty);
	assert(bytes[bytes.len - 4:4] == unhex("FF FF FF FF"), "a null array is written as -1");
	assert(bytes[2 + 8 + 4 + 4:4] == unhex("FF FF FF FF"), "a null string is written as -1");
	Decoder d = decoder(bytes, tmem);
	CallRequest back = d.get_call_request()!!;
	assert(back.methods_to_call.ptr == null && is_null(back.request_header.audit_entry_id));
	assert(enc_call_request(back) == bytes);
	// an empty array is not a null array
	CallMethodRequest[1] store;
	CallRequest zero = { .methods_to_call = store[:0] };
	char[] z = enc_call_request(zero);
	assert(z[z.len - 4:4] == unhex("00 00 00 00"));
	Decoder zd = decoder(z, tmem);
	CallRequest zb = zd.get_call_request()!!;
	assert(zb.methods_to_call.ptr != null && zb.methods_to_call.len == 0);
	// default-initialised structures encode without a fault
	ApplicationDescription app;
	Encoder e = encoder_sizer();
	e.put_application_description(app)!!;
	assert(e.written == 4 + 4 + 1 + 4 + 4 + 4 + 4);       // five null strings (one of them an array), a LocalizedText, the type
}

// ---------- limits ----------
fn void limits_hostile_array_lengths() @test
{
	char[256] store;
	ArenaAllocator arena;
	arena.init(&store);
	// CallRequest with a header and an array length of 10^9 and no data: no allocation
	char[] hostile = cat(enc_call_request({})[:enc_call_request({}).len - 4], unhex("00 CA 9A 3B"));
	Decoder d = decoder(hostile, &arena);
	assert(@fails(d.get_call_request(), BAD_LENGTH));
	assert(arena.used == 0);
	char[] truncated = cat(enc_call_request({})[:enc_call_request({}).len - 4], unhex("40 42 0F 00"));    // 1_000_000 elements, nothing behind
	Decoder t = decoder(truncated, &arena);
	assert(@fails(t.get_call_request(), TRUNCATED));
	assert(arena.used == 0);
	Decoder depth = dec("00");
	depth.depth = 32;
	assert(@fails(depth.get_read_request(), DEPTH_EXCEEDED));
}
