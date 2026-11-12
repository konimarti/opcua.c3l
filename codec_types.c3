module opcua;

// Structured built-in types (OPC 10000-6 5.2.2.5, 5.2.2.10 - 5.2.2.15, 5.2.2.17).

const uint MAX_ENCODE_DEPTH = 100;

fn void? Encoder.enter(&self)
{
	if (self.depth >= MAX_ENCODE_DEPTH) return DEPTH_EXCEEDED~;
	self.depth++;
}

fn void Encoder.leave(&self) => self.depth--;

// ---------- DateTime ----------
fn void? Encoder.put_datetime(&self, UaDateTime v) => self.put_u64((ulong)(long)v);
fn UaDateTime? Decoder.get_datetime(&self) => (UaDateTime)(long)self.get_u64()!;

const long UA_UNIX_EPOCH_TICKS = 116444736000000000;      // 1970-01-01 in ticks since 1601
const long UA_TICKS_PER_MS = 10000;
const long UA_UNIX_EPOCH_MS = 11644473600000;             // milliseconds between 1601-01-01 and 1970-01-01

// Saturating: milliseconds before 1601 give 0 ("not specified"), beyond the range give long::max. Never overflows.
fn UaDateTime datetime_from_unix_ms(long unix_ms)
{
	if (unix_ms < -UA_UNIX_EPOCH_MS) return (UaDateTime)0;
	long ms = unix_ms + UA_UNIX_EPOCH_MS;                   // >= 0, cannot overflow for unix_ms <= long::max - epoch
	if (unix_ms > long::max - UA_UNIX_EPOCH_MS) return (UaDateTime)long::max;
	if (ms > long::max / UA_TICKS_PER_MS) return (UaDateTime)long::max;
	return (UaDateTime)(ms * UA_TICKS_PER_MS);
}

// Values <= 0 are "not specified" and map to the 1601 epoch. Never overflows.
fn long datetime_to_unix_ms(UaDateTime t)
{
	long ticks = (long)t;
	if (ticks < 0) ticks = 0;
	return ticks / UA_TICKS_PER_MS - UA_UNIX_EPOCH_MS;
}

// ---------- QualifiedName ----------
fn void? Encoder.put_qualified_name(&self, QualifiedName v)
{
	self.put_u16(v.ns)!;
	self.put_string(v.name)!;
}

fn QualifiedName? Decoder.get_qualified_name(&self)
{
	QualifiedName q;
	q.ns = self.get_u16()!;
	q.name = self.get_string()!;
	return q;
}

// ---------- LocalizedText: mask 0x01 locale, 0x02 text; other bits are reserved ----------
fn void? Encoder.put_localized_text(&self, LocalizedText v)
{
	char mask = 0;
	if (!is_null(v.locale)) mask |= 0x01;
	if (!is_null(v.text)) mask |= 0x02;
	self.put_u8(mask)!;
	if (mask & 0x01) self.put_string(v.locale)!;
	if (mask & 0x02) self.put_string(v.text)!;
}

fn LocalizedText? Decoder.get_localized_text(&self)
{
	char mask = self.get_u8()!;
	if ((mask & 0xFC) != 0) return BAD_ENCODING~;
	LocalizedText t;
	if (mask & 0x01) t.locale = self.get_string()!;
	if (mask & 0x02) t.text = self.get_string()!;
	return t;
}

// ---------- ExpandedNodeId: NodeId encoding byte | 0x80 (NamespaceUri follows) | 0x40 (ServerIndex follows) ----------
fn void? Encoder.put_expanded_nodeid(&self, ExpandedNodeId v)
{
	char flags = 0;
	if (!is_null(v.namespace_uri)) flags |= 0x80;
	if (v.server_index != 0) flags |= 0x40;
	self.put_nodeid_flagged(v.id, flags)!;
	if (flags & 0x80) self.put_string(v.namespace_uri)!;
	if (flags & 0x40) self.put_u32(v.server_index)!;
}

fn ExpandedNodeId? Decoder.get_expanded_nodeid(&self)
{
	char flags;
	ExpandedNodeId x;
	x.id = self.get_nodeid_flagged(&flags)!;
	if (flags & 0x80) x.namespace_uri = self.get_string()!;
	if (flags & 0x40) x.server_index = self.get_u32()!;
	return x;
}

// ---------- ExtensionObject: TypeId NodeId, encoding byte (0 none, 1 ByteString, 2 XmlElement), body ----------
fn void? Encoder.put_extension_object(&self, ExtensionObject v)
{
	if (v.encoding > 2) return BAD_ENCODING~;
	self.put_nodeid(v.type_id)!;
	self.put_u8(v.encoding)!;
	if (v.encoding != 0) self.put_bytestring(v.body)!;
}

fn ExtensionObject? Decoder.get_extension_object(&self)
{
	ExtensionObject x;
	x.type_id = self.get_nodeid()!;
	x.encoding = self.get_u8()!;
	if (x.encoding > 2) return BAD_ENCODING~;
	if (x.encoding != 0) x.body = self.get_bytestring()!;
	return x;
}

// ---------- DiagnosticInfo ----------
// Wire order of the fields. The mask bits are SymbolicId 0x01, NamespaceUri 0x02, LocalizedText 0x04, Locale 0x08,
// AdditionalInfo 0x10, InnerStatusCode 0x20, InnerDiagnosticInfo 0x40; fields follow in bit order. Some descriptions list
// Locale before LocalizedText on the wire: that is NOT confirmed against the specification text. Flipping this constant
// swaps the two Int32 fields on the wire, nothing else changes.
const bool DIAG_LOCALE_BEFORE_TEXT = false;

fn void? Encoder.put_diagnostic_info(&self, DiagnosticInfo v)
{
	self.enter()!;
	defer self.leave();
	char mask = v.present & 0x0F;
	if (!is_null(v.additional_info)) mask |= 0x10;
	if (v.inner_status != STATUS_GOOD) mask |= 0x20;
	if (v.inner != null) mask |= 0x40;
	self.put_u8(mask)!;
	if (mask & 0x01) self.put_u32((uint)v.symbolic_id)!;
	if (mask & 0x02) self.put_u32((uint)v.namespace_uri)!;
	$if DIAG_LOCALE_BEFORE_TEXT:
		if (mask & 0x08) self.put_u32((uint)v.locale)!;
		if (mask & 0x04) self.put_u32((uint)v.localized_text)!;
	$else
		if (mask & 0x04) self.put_u32((uint)v.localized_text)!;
		if (mask & 0x08) self.put_u32((uint)v.locale)!;
	$endif
	if (mask & 0x10) self.put_string(v.additional_info)!;
	if (mask & 0x20) self.put_u32((uint)v.inner_status)!;
	if (mask & 0x40) self.put_diagnostic_info(*v.inner)!;
}

fn DiagnosticInfo? Decoder.get_diagnostic_info(&self)
{
	self.enter()!;
	defer self.leave();
	char mask = self.get_u8()!;
	if ((mask & 0x80) != 0) return BAD_ENCODING~;
	DiagnosticInfo d;
	d.present = mask & 0x0F;
	if (mask & 0x01) d.symbolic_id = (int)self.get_u32()!;
	if (mask & 0x02) d.namespace_uri = (int)self.get_u32()!;
	$if DIAG_LOCALE_BEFORE_TEXT:
		if (mask & 0x08) d.locale = (int)self.get_u32()!;
		if (mask & 0x04) d.localized_text = (int)self.get_u32()!;
	$else
		if (mask & 0x04) d.localized_text = (int)self.get_u32()!;
		if (mask & 0x08) d.locale = (int)self.get_u32()!;
	$endif
	if (mask & 0x10) d.additional_info = self.get_string()!;
	if (mask & 0x20) d.inner_status = (StatusCode)self.get_u32()!;
	if (mask & 0x40)
	{
		d.inner = alloc::new_try(self.allocator, DiagnosticInfo)!;
		*d.inner = self.get_diagnostic_info()!;
	}
	return d;
}

// ---------- DataValue: mask 0x01 Value, 0x02 StatusCode, 0x04 SourceTimestamp, 0x08 ServerTimestamp,
// 0x10 SourcePicoseconds, 0x20 ServerPicoseconds; fields in this order ----------
fn void? Encoder.put_data_value(&self, DataValue v)
{
	self.enter()!;
	defer self.leave();
	char mask = 0;
	if (v.has_value) mask |= 0x01;
	if (v.status != STATUS_GOOD) mask |= 0x02;
	if ((long)v.source_ts != 0) mask |= 0x04;
	if ((long)v.server_ts != 0) mask |= 0x08;
	if (v.source_pico != 0) mask |= 0x10;
	if (v.server_pico != 0) mask |= 0x20;
	self.put_u8(mask)!;
	if (mask & 0x01) self.put_variant(v.value)!;
	if (mask & 0x02) self.put_u32((uint)v.status)!;
	if (mask & 0x04) self.put_datetime(v.source_ts)!;
	if (mask & 0x08) self.put_datetime(v.server_ts)!;
	if (mask & 0x10) self.put_u16(v.source_pico)!;
	if (mask & 0x20) self.put_u16(v.server_pico)!;
}

fn DataValue? Decoder.get_data_value(&self)
{
	self.enter()!;
	defer self.leave();
	char mask = self.get_u8()!;
	if ((mask & 0xC0) != 0) return BAD_ENCODING~;
	DataValue v;
	if (mask & 0x01)
	{
		v.value = self.get_variant()!;
		v.has_value = true;
	}
	if (mask & 0x02) v.status = (StatusCode)self.get_u32()!;
	if (mask & 0x04) v.source_ts = self.get_datetime()!;
	if (mask & 0x08) v.server_ts = self.get_datetime()!;
	if (mask & 0x10) v.source_pico = self.get_u16()!;
	if (mask & 0x20) v.server_pico = self.get_u16()!;
	return v;
}
