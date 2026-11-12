module uagen;
import std::collections::list;
import std::collections::map;
import std::collections::set;
import std::encoding::xml;

faultdef
	UAGEN_UNKNOWN_TYPE,
	UAGEN_UNSUPPORTED_CONSTRUCT,
	UAGEN_FILE_ERROR,
	UAGEN_XML_ERROR,
	UAGEN_CSV_ERROR,
	UAGEN_INVALID_ARGS;

struct Field
{
	String name;
	String type_name;
	bool is_array;
	String length_field;
	String switch_field;
	String switch_value;
	String switch_operand;
	String length;
	String source_type;
}

struct StructuredType
{
	String name;
	String base_type;
	List{Field} fields;
}

struct EnumValue
{
	String name;
	long value;
}

struct EnumeratedType
{
	String name;
	int length_in_bits;
	bool is_option_set;
	List{EnumValue} values;
}

struct TypeTable
{
	Allocator allocator;
	XmlDocument* doc;
	HashMap{String, StructuredType*} structures;
	HashMap{String, EnumeratedType*} enums;
	HashSet{String} opaques;
	List{String} struct_names;
	List{String} enum_names;
	List{String} opaque_names;
	HashSet{String} field_attrib_names;
}

fn void TypeTable.init(&self, Allocator allocator)
{
	self.allocator = allocator;
	self.structures.init(allocator);
	self.enums.init(allocator);
	self.opaques.init(allocator);
	self.struct_names.init(allocator);
	self.enum_names.init(allocator);
	self.opaque_names.init(allocator);
	self.field_attrib_names.init(allocator);
}

fn void TypeTable.free(&self)
{
	foreach (st : self.structures.value_iter())
	{
		st.fields.free();
		alloc::free(self.allocator, st);
	}
	self.structures.free();

	foreach (en : self.enums.value_iter())
	{
		en.values.free();
		alloc::free(self.allocator, en);
	}
	self.enums.free();

	self.opaques.free();
	self.struct_names.free();
	self.enum_names.free();
	self.opaque_names.free();
	self.field_attrib_names.free();
	if (self.doc != null)
	{
		self.doc.free();
	}
}

String last_error_msg = "";
char[256] last_error_buf;

fn void set_last_error(String msg)
{
	sz copy_len = msg.len < last_error_buf.len ? msg.len : last_error_buf.len;
	mem::copy(&last_error_buf, msg.ptr, copy_len);
	last_error_msg = (String)last_error_buf[:copy_len];
}
