module opcua;

// Sweeps over every structured vector: all proper prefixes fail with TRUNCATED, the sizer agrees with the encoder, and
// decoding then encoding gives the same bytes.

fn void prefix_sweep_structured() @test
{
	foreach (v : TYPE_VECTORS) prefix_sweep(v.hex, v.kind);
}

fn void sizer_structured() @test
{
	foreach (v : TYPE_VECTORS) assert(sizer_of(v.hex, v.kind) == reencode(v.hex, v.kind).len);
}

fn void sizer_all_variant_types() @test
{
	for (char id = 1; id <= 25; id++)
	{
		for (int a = 0; a < 2; a++)
		{
			BuiltIn t = (BuiltIn)id;
			if (t == VARIANT && a == 0) continue;
			Variant v = sample(t, a == 1);
			Encoder e = encoder_sizer();
			e.put_variant(v)!!;
			assert(e.written == enc_variant(v).len);
		}
	}
}

fn void roundtrip_structured() @test
{
	foreach (v : TYPE_VECTORS) assert(reencode(v.hex, v.kind) == unhex(v.hex));
}
