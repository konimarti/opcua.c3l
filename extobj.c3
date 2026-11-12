module opcua;

// An ExtensionObject keeps its body as received. For a known structure the body is a binary encoding of that structure:
// decode it with a decoder over the body only, so a body shorter than the structure is TRUNCATED, and bytes after the
// structure (a newer revision with more fields) stay behind in the body decoder and never reach the outer stream.
fn Decoder? extobj_body_decoder(ExtensionObject* eo, Allocator allocator, Limits limits = default_limits())
{
	if (eo.encoding != 1 || bytes_is_null(eo.body)) return BAD_ENCODING~;
	return decoder(eo.body, allocator, limits);
}
