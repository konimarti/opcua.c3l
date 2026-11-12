module opcua;

// Fixtures: reviewer vectors V1-V9, V21, V22 plus designer extras (OPC 10000-6 5.2.2.1 - 5.2.2.3).

fn void fixtures_boolean() @test
{
	assert(enc_bool(true) == unhex("01"));            // V1
	assert(enc_bool(false) == unhex("00"));
	Decoder d1 = dec("01");
	assert(d1.get_bool()!!);
	Decoder d2 = dec("02");                           // V2: any non-zero is true, the encoder writes 01
	assert(d2.get_bool()!!);
	assert(enc_bool(d2.input.len > 0) == unhex("01"));
	Decoder d3 = dec("00");
	assert(!d3.get_bool()!!);
}

fn void fixtures_integers() @test
{
	assert(enc_u32((uint)(-2)) == unhex("FE FF FF FF"));      // V3
	Decoder d3 = dec("FE FF FF FF");
	assert((int)d3.get_u32()!! == -2);
	assert(enc_u32(0x12345678) == unhex("78 56 34 12"));      // V4
	Decoder d4 = dec("78 56 34 12");
	assert(d4.get_u32()!! == 0x12345678);
	assert(enc_u16(0x1234) == unhex("34 12"));
	Decoder d5 = dec("34 12");
	assert(d5.get_u16()!! == 0x1234);
	assert(enc_u64(1) == unhex("01 00 00 00 00 00 00 00"));
	Decoder d6 = dec("01 00 00 00 00 00 00 00");
	assert(d6.get_u64()!! == 1);
	assert(enc_u64(0x0102030405060708) == unhex("08 07 06 05 04 03 02 01"));
	Decoder d7 = dec("08 07 06 05 04 03 02 01");
	assert(d7.get_u64()!! == 0x0102030405060708);
}

fn void fixtures_floats() @test
{
	assert(enc_f32(1.5f) == unhex("00 00 C0 3F"));            // V5
	Decoder d1 = dec("00 00 C0 3F");
	assert(d1.get_f32()!! == 1.5f);
	assert(enc_f32(-6.5f) == unhex("00 00 D0 C0"));           // designer extra
	assert(enc_f64(1.0) == unhex("00 00 00 00 00 00 F0 3F")); // V6
	Decoder d2 = dec("00 00 00 00 00 00 F0 3F");
	assert(d2.get_f64()!! == 1.0);
	assert(enc_f64(-2.5) == unhex("00 00 00 00 00 00 04 C0")); // V7
	Decoder d3 = dec("00 00 00 00 00 00 04 C0");
	assert(d3.get_f64()!! == -2.5);
	Decoder d4 = dec("00 00 00 00 00 00 F0 7F");              // V8: +Inf
	double inf = d4.get_f64()!!;
	assert(inf > 1.0e308 * 10.0 || inf == double::inf);
	assert(enc_f64(inf) == unhex("00 00 00 00 00 00 F0 7F"));
}

// V9: a NaN payload survives decode -> encode bit for bit (no canonicalisation).
fn void nan_roundtrip_double() @test
{
	Decoder d = dec("01 00 00 00 00 00 F8 7F");
	double nan = d.get_f64()!!;
	assert(nan != nan);
	assert(enc_f64(nan) == unhex("01 00 00 00 00 00 F8 7F"));
}

fn void nan_roundtrip_float() @test
{
	Decoder d = dec("01 00 C0 7F");
	float nan = d.get_f32()!!;
	assert(nan != nan);
	assert(enc_f32(nan) == unhex("01 00 C0 7F"));
}

// V21 / V22: StatusCode is a UInt32 on the wire; unknown codes round trip and severity comes from the top two bits.
fn void fixtures_statuscode() @test
{
	Decoder good = dec("00 00 00 00");
	StatusCode g = (StatusCode)good.get_u32()!!;
	assert(g == STATUS_GOOD && status_is_good(g));
	Decoder bad = dec("00 00 34 80");
	StatusCode b = (StatusCode)bad.get_u32()!!;
	assert((uint)b == 0x80340000);
	assert(status_is_bad(b) && !status_is_good(b));
	assert(enc_u32((uint)b) == unhex("00 00 34 80"));
	StatusCode info = (StatusCode)0x00000040;                // Good with info bits set is still Good
	assert(status_is_good(info));
	assert(status_is_uncertain((StatusCode)0x40000000));
}

fn void prefix_sweep_primitives() @test
{
	prefix_sweep("01", BOOL);
	prefix_sweep("34 12", U16);
	prefix_sweep("FE FF FF FF", U32);
	prefix_sweep("01 00 00 00 00 00 00 00", U64);
	prefix_sweep("00 00 C0 3F", F32);
	prefix_sweep("00 00 00 00 00 00 F0 3F", F64);
	prefix_sweep("01 00 00 00 00 00 F8 7F", F64);
	prefix_sweep("00 00 34 80", U32);
}

fn void sizer_primitives() @test
{
	Encoder e = encoder_sizer();
	e.put_bool(true)!!;
	e.put_u16(1)!!;
	e.put_u32(1)!!;
	e.put_u64(1)!!;
	e.put_f32(1.0f)!!;
	e.put_f64(1.0)!!;
	assert(e.written == 1 + 2 + 4 + 8 + 4 + 8);
}

fn void bytebuf_growth_and_patch() @test
{
	ByteBuf b;
	b.init(tmem, 4);
	Encoder e = encoder(&b);
	for (int i = 0; i < 1000; i++) e.put_u32((uint)i)!!;
	assert(b.len == 4000);
	assert(e.written == 4000);
	b.patch_u32(0, 0xAABBCCDD)!!;
	assert(b.bytes()[:4] == unhex("DD CC BB AA"));
	b.patch_u32(3996, 7)!!;
	assert(b.bytes()[3996:4] == unhex("07 00 00 00"));
	assert(@fails(b.patch_u32(3998, 1), BUFFER_FULL));
	b.clear();
	assert(b.len == 0);
}
