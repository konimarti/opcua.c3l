module opcua;

// DiagnosticInfo (OPC 10000-6 5.2.2.12). Vectors DI1-DI6, M63-M65.
//
// Open point: the order of the Locale and LocalizedText Int32 fields on the wire. The implementation writes the fields in
// mask-bit order (SymbolicId 0x01, NamespaceUri 0x02, LocalizedText 0x04, Locale 0x08, AdditionalInfo 0x10, InnerStatusCode
// 0x20, InnerDiagnosticInfo 0x40). Some descriptions list Locale before LocalizedText; this is NOT confirmed against the
// specification text. The constant DIAG_LOCALE_BEFORE_TEXT swaps the two fields; test diag_order below follows the
// constant, so a flip is a one-line change (plus the DI6 hex in the first test).

fn void fixtures_diagnostic_info() @test
{
	assert(enc_diag({}) == unhex("00"));                                                  // DI1
	check_vector("00", DIAG);
	DiagnosticInfo d2 = { .present = 0x01, .symbolic_id = 5 };
	assert(enc_diag(d2) == unhex("01 05 00 00 00"));                                      // DI2
	check_vector("01 05 00 00 00", DIAG);
	DiagnosticInfo d3 = { .additional_info = "hi" };
	assert(enc_diag(d3) == unhex("10 02 00 00 00 68 69"));                                // DI3
	check_vector("10 02 00 00 00 68 69", DIAG);
	DiagnosticInfo d4 = { .inner_status = (StatusCode)0x80340000 };
	assert(enc_diag(d4) == unhex("20 00 00 34 80"));                                      // DI4
	check_vector("20 00 00 34 80", DIAG);
	DiagnosticInfo inner = { .inner_status = (StatusCode)0x80340000 };
	DiagnosticInfo d5 = { .inner = &inner };
	assert(enc_diag(d5) == unhex("40 20 00 00 34 80"));                                   // DI5
	check_vector("40 20 00 00 34 80", DIAG);
}

// An index of 0 is a valid string table index and is not the same as an absent field.
fn void diag_zero_index_is_present() @test
{
	DiagnosticInfo d = { .present = 0x01, .symbolic_id = 0 };
	assert(enc_diag(d) == unhex("01 00 00 00 00"));
	check_vector("01 00 00 00 00", DIAG);
	Decoder dd = dec("01 00 00 00 00");
	DiagnosticInfo r = dd.get_diagnostic_info()!!;
	assert((r.present & 0x01) != 0 && r.symbolic_id == 0);
	DiagnosticInfo none = { .symbolic_id = 0 };
	assert(enc_diag(none) == unhex("00"));
}

// DI6: all four Int32 fields plus AdditionalInfo (mask 0x1F). The hex assumes mask-bit order.
fn void diag_order() @test
{
	String di6 = "1F 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 01 00 00 00 41";
	Decoder d = dec(di6);
	DiagnosticInfo r = d.get_diagnostic_info()!!;
	int text = DIAG_LOCALE_BEFORE_TEXT ? 4 : 3;
	int locale = DIAG_LOCALE_BEFORE_TEXT ? 3 : 4;
	assert(r.symbolic_id == 1 && r.namespace_uri == 2);
	assert(r.localized_text == text && r.locale == locale);
	assert(r.additional_info == "A");
	check_vector(di6, DIAG);
	DiagnosticInfo built = { .present = 0x0F, .symbolic_id = 1, .namespace_uri = 2, .localized_text = text, .locale = locale, .additional_info = "A" };
	assert(enc_diag(built) == unhex(di6));
}

fn void diag_nested() @test
{
	DiagnosticInfo l3 = { .present = 0x01, .symbolic_id = 3 };
	DiagnosticInfo l2 = { .present = 0x01, .symbolic_id = 2, .inner = &l3 };
	DiagnosticInfo l1 = { .present = 0x01, .symbolic_id = 1, .inner = &l2 };
	String hex = tohex(enc_diag(l1));
	check_vector(hex, DIAG);
	Decoder d = dec(hex);
	DiagnosticInfo r = d.get_diagnostic_info()!!;
	assert(r.inner != null && r.inner.inner != null && r.inner.inner.symbolic_id == 3 && r.inner.inner.inner == null);
}

fn void errors_diagnostic_info() @test
{
	DString chain = dstring::temp();
	for (int i = 0; i < 1000; i++) chain.append("40 ");
	assert(fails_with(chain.str_view(), DIAG, DEPTH_EXCEEDED));                           // M63: inner chain
	assert(fails_with("80", DIAG, BAD_ENCODING));                                         // M64: reserved bit
	assert(fails_with("10 FF FF FF 7F", DIAG, BAD_LENGTH));                               // M65: huge AdditionalInfo
	assert(fails_with("01 05", DIAG, TRUNCATED));
	assert(fails_with("", DIAG, TRUNCATED));
}

fn void diag_depth_boundary() @test
{
	// 31 nested levels are fine (depth 32 with the outermost), one more is not
	DString ok = dstring::temp();
	for (int i = 0; i < 31; i++) ok.append("40 ");
	ok.append("00");
	assert(decodes_fully(ok.str_view(), DIAG));
	DString too_deep = dstring::temp();
	for (int i = 0; i < 32; i++) too_deep.append("40 ");
	too_deep.append("00");
	assert(fails_with(too_deep.str_view(), DIAG, DEPTH_EXCEEDED));
}
