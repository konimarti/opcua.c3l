module opcua;

// Variant (OPC 10000-6 5.2.2.16): mask bits 0-5 = built-in type id, 0x40 = ArrayDimensions follow the values,
// 0x80 = array (Int32 length, -1 = null, then the elements without per-element masks).

fn Variant variant_bool(bool v) => { .type = BOOLEAN, .scalar.b = v };
fn Variant variant_u32(uint v) => { .type = UINT32, .scalar.u32 = v };
fn Variant variant_i32(int v) => { .type = INT32, .scalar.i32 = v };
fn Variant variant_f64(double v) => { .type = DOUBLE, .scalar.f64 = v };
fn Variant variant_string(String v) => { .type = STRING, .scalar.str = v };
fn Variant variant_i32_array(int[] v) => { .type = INT32, .is_array = true, .array.i32 = v };
fn Variant variant_f64_array(double[] v) => { .type = DOUBLE, .is_array = true, .array.f64 = v };

// Number of array elements (a null array has 0).
fn sz array_data_len(BuiltIn t, ArrayData* a)
{
	switch (t)
	{
		case BOOLEAN: return a.b.len;
		case SBYTE: return a.i8.len;
		case BYTE: return a.u8.len;
		case INT16: return a.i16.len;
		case UINT16: return a.u16.len;
		case INT32: return a.i32.len;
		case UINT32: return a.u32.len;
		case INT64: return a.i64.len;
		case UINT64: return a.u64.len;
		case FLOAT: return a.f32.len;
		case DOUBLE: return a.f64.len;
		case STRING: return a.str.len;
		case DATETIME: return a.dt.len;
		case GUID: return a.guid.len;
		case BYTESTRING: return a.bytes.len;
		case XMLELEMENT: return a.str.len;
		case NODEID: return a.node_id.len;
		case EXPANDEDNODEID: return a.xnode_id.len;
		case STATUSCODE: return a.sc.len;
		case QUALIFIEDNAME: return a.qname.len;
		case LOCALIZEDTEXT: return a.ltext.len;
		case EXTENSIONOBJECT: return a.ext.len;
		case DATAVALUE: return a.dv.len;
		case VARIANT: return a.variant.len;
		case DIAGNOSTICINFO: return a.diag.len;
		default: return 0;
	}
}

fn bool array_data_is_null(BuiltIn t, ArrayData* a)
{
	switch (t)
	{
		case BOOLEAN: return a.b.ptr == null;
		case SBYTE: return a.i8.ptr == null;
		case BYTE: return a.u8.ptr == null;
		case INT16: return a.i16.ptr == null;
		case UINT16: return a.u16.ptr == null;
		case INT32: return a.i32.ptr == null;
		case UINT32: return a.u32.ptr == null;
		case INT64: return a.i64.ptr == null;
		case UINT64: return a.u64.ptr == null;
		case FLOAT: return a.f32.ptr == null;
		case DOUBLE: return a.f64.ptr == null;
		case STRING: return a.str.ptr == null;
		case DATETIME: return a.dt.ptr == null;
		case GUID: return a.guid.ptr == null;
		case BYTESTRING: return a.bytes.ptr == null;
		case XMLELEMENT: return a.str.ptr == null;
		case NODEID: return a.node_id.ptr == null;
		case EXPANDEDNODEID: return a.xnode_id.ptr == null;
		case STATUSCODE: return a.sc.ptr == null;
		case QUALIFIEDNAME: return a.qname.ptr == null;
		case LOCALIZEDTEXT: return a.ltext.ptr == null;
		case EXTENSIONOBJECT: return a.ext.ptr == null;
		case DATAVALUE: return a.dv.ptr == null;
		case VARIANT: return a.variant.ptr == null;
		case DIAGNOSTICINFO: return a.diag.ptr == null;
		default: return true;
	}
}

fn sz Variant.count(&self)
{
	if (self.type == EMPTY) return 0;
	if (!self.is_array) return 1;
	return array_data_len(self.type, &self.array);
}

// Smallest wire size of one element: bounds the array length by the remaining input before anything is allocated.
fn sz element_min_size(BuiltIn t)
{
	switch (t)
	{
		case BOOLEAN:
		case SBYTE:
		case BYTE: return 1;
		case INT16:
		case UINT16: return 2;
		case INT32:
		case UINT32:
		case FLOAT:
		case STATUSCODE:
		case STRING:
		case BYTESTRING:
		case XMLELEMENT: return 4;
		case INT64:
		case UINT64:
		case DOUBLE:
		case DATETIME: return 8;
		case GUID: return 16;
		case NODEID:
		case EXPANDEDNODEID: return 2;
		case QUALIFIEDNAME: return 6;
		case EXTENSIONOBJECT: return 3;
		case LOCALIZEDTEXT:
		case DATAVALUE:
		case VARIANT:
		case DIAGNOSTICINFO: return 1;
		default: return 1;
	}
}

// ---------- encoding ----------
fn void? Encoder.put_scalar(&self, BuiltIn t, Scalar* s)
{
	switch (t)
	{
		case BOOLEAN: self.put_bool(s.b)!;
		case SBYTE: self.put_u8((char)s.i8)!;
		case BYTE: self.put_u8(s.u8)!;
		case INT16: self.put_u16((ushort)s.i16)!;
		case UINT16: self.put_u16(s.u16)!;
		case INT32: self.put_u32((uint)s.i32)!;
		case UINT32: self.put_u32(s.u32)!;
		case INT64: self.put_u64((ulong)s.i64)!;
		case UINT64: self.put_u64(s.u64)!;
		case FLOAT: self.put_f32(s.f32)!;
		case DOUBLE: self.put_f64(s.f64)!;
		case STRING: self.put_string(s.str)!;
		case XMLELEMENT: self.put_string(s.str)!;
		case DATETIME: self.put_datetime(s.dt)!;
		case GUID: self.put_guid(s.guid)!;
		case BYTESTRING: self.put_bytestring(s.bytes)!;
		case NODEID: self.put_nodeid(*s.node_id)!;
		case EXPANDEDNODEID: self.put_expanded_nodeid(*s.xnode_id)!;
		case STATUSCODE: self.put_u32((uint)s.sc)!;
		case QUALIFIEDNAME: self.put_qualified_name(*s.qname)!;
		case LOCALIZEDTEXT: self.put_localized_text(*s.ltext)!;
		case EXTENSIONOBJECT: self.put_extension_object(*s.ext)!;
		case DATAVALUE: self.put_data_value(*s.dv)!;
		case DIAGNOSTICINFO: self.put_diagnostic_info(*s.diag)!;
		default: return BAD_ENCODING~;
	}
}

fn void? Encoder.put_array_data(&self, BuiltIn t, ArrayData* a)
{
	switch (t)
	{
		case BOOLEAN: foreach (x : a.b) self.put_bool(x)!;
		case SBYTE: foreach (x : a.i8) self.put_u8((char)x)!;
		case BYTE: self.put_raw(a.u8)!;
		case INT16: foreach (x : a.i16) self.put_u16((ushort)x)!;
		case UINT16: foreach (x : a.u16) self.put_u16(x)!;
		case INT32: foreach (x : a.i32) self.put_u32((uint)x)!;
		case UINT32: foreach (x : a.u32) self.put_u32(x)!;
		case INT64: foreach (x : a.i64) self.put_u64((ulong)x)!;
		case UINT64: foreach (x : a.u64) self.put_u64(x)!;
		case FLOAT: foreach (x : a.f32) self.put_f32(x)!;
		case DOUBLE: foreach (x : a.f64) self.put_f64(x)!;
		case STRING: foreach (x : a.str) self.put_string(x)!;
		case XMLELEMENT: foreach (x : a.str) self.put_string(x)!;
		case DATETIME: foreach (x : a.dt) self.put_datetime(x)!;
		case GUID: foreach (x : a.guid) self.put_guid(x)!;
		case BYTESTRING: foreach (x : a.bytes) self.put_bytestring(x)!;
		case NODEID: foreach (x : a.node_id) self.put_nodeid(x)!;
		case EXPANDEDNODEID: foreach (x : a.xnode_id) self.put_expanded_nodeid(x)!;
		case STATUSCODE: foreach (x : a.sc) self.put_u32((uint)x)!;
		case QUALIFIEDNAME: foreach (x : a.qname) self.put_qualified_name(x)!;
		case LOCALIZEDTEXT: foreach (x : a.ltext) self.put_localized_text(x)!;
		case EXTENSIONOBJECT: foreach (x : a.ext) self.put_extension_object(x)!;
		case DATAVALUE: foreach (x : a.dv) self.put_data_value(x)!;
		case VARIANT: foreach (x : a.variant) self.put_variant(x)!;
		case DIAGNOSTICINFO: foreach (x : a.diag) self.put_diagnostic_info(x)!;
		default: return BAD_ENCODING~;
	}
}

fn void? Encoder.put_variant(&self, Variant v)
{
	self.enter()!;
	defer self.leave();
	char tid = (char)v.type;
	if (tid > 25) return BAD_ENCODING~;
	if (v.type == EMPTY)
	{
		if (v.is_array || v.dims.len > 0) return BAD_ENCODING~;
		return self.put_u8(0);
	}
	if (v.dims.len > 0 && !v.is_array) return BAD_ENCODING~;
	if (v.type == VARIANT && !v.is_array) return BAD_ENCODING~;       // a scalar Variant inside a Variant is not allowed
	char mask = tid;
	if (v.is_array) mask |= 0x80;
	if (v.dims.len > 0) mask |= 0x40;
	self.put_u8(mask)!;
	if (!v.is_array)
	{
		self.put_scalar(v.type, &v.scalar)!;
		return;
	}
	sz n = array_data_len(v.type, &v.array);
	self.put_array_len(n, array_data_is_null(v.type, &v.array))!;
	self.put_array_data(v.type, &v.array)!;
	if (v.dims.len > 0)
	{
		ulong prod = 1;
		foreach (d : v.dims)
		{
			prod *= (ulong)d;
			if (prod > (ulong)int::max) return BAD_LENGTH~;
		}
		if (prod != (ulong)n) return BAD_LENGTH~;
		self.put_array_len(v.dims.len)!;
		foreach (d : v.dims) self.put_u32(d)!;
	}
}

// ---------- decoding ----------
macro new_slice(Allocator a, $Type, int n)
{
	return alloc::new_array_try(a, $Type, (sz)(n == 0 ? 1 : n))![:(sz)n];
}

fn void? Decoder.get_scalar(&self, BuiltIn t, Scalar* s)
{
	switch (t)
	{
		case BOOLEAN: s.b = self.get_bool()!;
		case SBYTE: s.i8 = (ichar)self.get_u8()!;
		case BYTE: s.u8 = self.get_u8()!;
		case INT16: s.i16 = (short)self.get_u16()!;
		case UINT16: s.u16 = self.get_u16()!;
		case INT32: s.i32 = (int)self.get_u32()!;
		case UINT32: s.u32 = self.get_u32()!;
		case INT64: s.i64 = (long)self.get_u64()!;
		case UINT64: s.u64 = self.get_u64()!;
		case FLOAT: s.f32 = self.get_f32()!;
		case DOUBLE: s.f64 = self.get_f64()!;
		case STRING: s.str = self.get_string()!;
		case XMLELEMENT: s.str = self.get_string()!;
		case DATETIME: s.dt = self.get_datetime()!;
		case GUID: s.guid = self.get_guid()!;
		case BYTESTRING: s.bytes = self.get_bytestring()!;
		case STATUSCODE: s.sc = (StatusCode)self.get_u32()!;
		case NODEID:
			s.node_id = alloc::new_try(self.allocator, NodeId)!;
			*s.node_id = self.get_nodeid()!;
		case EXPANDEDNODEID:
			s.xnode_id = alloc::new_try(self.allocator, ExpandedNodeId)!;
			*s.xnode_id = self.get_expanded_nodeid()!;
		case QUALIFIEDNAME:
			s.qname = alloc::new_try(self.allocator, QualifiedName)!;
			*s.qname = self.get_qualified_name()!;
		case LOCALIZEDTEXT:
			s.ltext = alloc::new_try(self.allocator, LocalizedText)!;
			*s.ltext = self.get_localized_text()!;
		case EXTENSIONOBJECT:
			s.ext = alloc::new_try(self.allocator, ExtensionObject)!;
			*s.ext = self.get_extension_object()!;
		case DATAVALUE:
			s.dv = alloc::new_try(self.allocator, DataValue)!;
			*s.dv = self.get_data_value()!;
		case DIAGNOSTICINFO:
			s.diag = alloc::new_try(self.allocator, DiagnosticInfo)!;
			*s.diag = self.get_diagnostic_info()!;
		default: return BAD_ENCODING~;
	}
}

fn void? Decoder.get_array_data(&self, BuiltIn t, int n, ArrayData* a)
{
	Allocator al = self.allocator;
	switch (t)
	{
		case BOOLEAN:
			a.b = new_slice(al, bool, n)!;
			foreach (&x : a.b) *x = self.get_bool()!;
		case SBYTE:
			a.i8 = new_slice(al, ichar, n)!;
			foreach (&x : a.i8) *x = (ichar)self.get_u8()!;
		case BYTE:
			a.u8 = new_slice(al, char, n)!;
			char[] raw = self.take((sz)n)!;
			if (n > 0) mem::copy(a.u8.ptr, raw.ptr, (sz)n);
		case INT16:
			a.i16 = new_slice(al, short, n)!;
			foreach (&x : a.i16) *x = (short)self.get_u16()!;
		case UINT16:
			a.u16 = new_slice(al, ushort, n)!;
			foreach (&x : a.u16) *x = self.get_u16()!;
		case INT32:
			a.i32 = new_slice(al, int, n)!;
			foreach (&x : a.i32) *x = (int)self.get_u32()!;
		case UINT32:
			a.u32 = new_slice(al, uint, n)!;
			foreach (&x : a.u32) *x = self.get_u32()!;
		case INT64:
			a.i64 = new_slice(al, long, n)!;
			foreach (&x : a.i64) *x = (long)self.get_u64()!;
		case UINT64:
			a.u64 = new_slice(al, ulong, n)!;
			foreach (&x : a.u64) *x = self.get_u64()!;
		case FLOAT:
			a.f32 = new_slice(al, float, n)!;
			foreach (&x : a.f32) *x = self.get_f32()!;
		case DOUBLE:
			a.f64 = new_slice(al, double, n)!;
			foreach (&x : a.f64) *x = self.get_f64()!;
		case STRING:
			a.str = new_slice(al, String, n)!;
			foreach (&x : a.str) *x = self.get_string()!;
		case XMLELEMENT:
			a.str = new_slice(al, String, n)!;
			foreach (&x : a.str) *x = self.get_string()!;
		case DATETIME:
			a.dt = new_slice(al, UaDateTime, n)!;
			foreach (&x : a.dt) *x = self.get_datetime()!;
		case GUID:
			a.guid = new_slice(al, Guid, n)!;
			foreach (&x : a.guid) *x = self.get_guid()!;
		case BYTESTRING:
			a.bytes = new_slice(al, char[], n)!;
			foreach (&x : a.bytes) *x = self.get_bytestring()!;
		case NODEID:
			a.node_id = new_slice(al, NodeId, n)!;
			foreach (&x : a.node_id) *x = self.get_nodeid()!;
		case EXPANDEDNODEID:
			a.xnode_id = new_slice(al, ExpandedNodeId, n)!;
			foreach (&x : a.xnode_id) *x = self.get_expanded_nodeid()!;
		case STATUSCODE:
			a.sc = new_slice(al, StatusCode, n)!;
			foreach (&x : a.sc) *x = (StatusCode)self.get_u32()!;
		case QUALIFIEDNAME:
			a.qname = new_slice(al, QualifiedName, n)!;
			foreach (&x : a.qname) *x = self.get_qualified_name()!;
		case LOCALIZEDTEXT:
			a.ltext = new_slice(al, LocalizedText, n)!;
			foreach (&x : a.ltext) *x = self.get_localized_text()!;
		case EXTENSIONOBJECT:
			a.ext = new_slice(al, ExtensionObject, n)!;
			foreach (&x : a.ext) *x = self.get_extension_object()!;
		case DATAVALUE:
			a.dv = new_slice(al, DataValue, n)!;
			foreach (&x : a.dv) *x = self.get_data_value()!;
		case VARIANT:
			a.variant = new_slice(al, Variant, n)!;
			foreach (&x : a.variant) *x = self.get_variant()!;
		case DIAGNOSTICINFO:
			a.diag = new_slice(al, DiagnosticInfo, n)!;
			foreach (&x : a.diag) *x = self.get_diagnostic_info()!;
		default: return BAD_ENCODING~;
	}
}

fn Variant? Decoder.get_variant(&self)
{
	self.enter()!;
	defer self.leave();
	char mask = self.get_u8()!;
	char tid = mask & 0x3F;
	bool arr = (mask & 0x80) != 0;
	bool has_dims = (mask & 0x40) != 0;
	if (tid > 25) return BAD_ENCODING~;
	if (has_dims && !arr) return BAD_ENCODING~;
	Variant v;
	v.type = (BuiltIn)tid;
	v.is_array = arr;
	if (tid == 0)
	{
		if (mask != 0) return BAD_ENCODING~;                       // array flag with the Null type
		return v;
	}
	if (!arr)
	{
		if (v.type == VARIANT) return BAD_ENCODING~;               // a scalar Variant inside a Variant is not allowed
		self.get_scalar(v.type, &v.scalar)!;
		return v;
	}
	int n = self.get_array_len(element_min_size(v.type))!;
	if (n >= 0) self.get_array_data(v.type, n, &v.array)!;
	if (has_dims)
	{
		int dn = self.get_array_len(4)!;
		if (dn < 1) return BAD_LENGTH~;
		uint[] dims = alloc::new_array_try(self.allocator, uint, (sz)dn)!;
		ulong prod = 1;
		foreach (&d : dims)
		{
			int x = (int)self.get_u32()!;
			if (x < 0) return BAD_LENGTH~;
			*d = (uint)x;
			prod *= (ulong)x;
			if (prod > (ulong)self.limits.max_matrix_elements) return BAD_LENGTH~;
		}
		if (prod != (ulong)(n < 0 ? 0 : n)) return BAD_LENGTH~;
		v.dims = dims;
	}
	return v;
}
