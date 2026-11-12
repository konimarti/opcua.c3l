module uagen;
import std::io::file;

macro bool @fails(#expr, fault expected)
{
	if (catch err = #expr) return err == expected;
	return false;
}

fn void parser_mini() @test
{
	char[] bytes = file::load(mem, "tools/uagen/testdata/mini.bsd")!!;
	defer mem::free(bytes.ptr);

	TypeTable table;
	table.init(mem);
	defer table.free();

	parse_bsd(&table, (String)bytes)!!;

	assert(table.struct_names.len() == 2);
	assert(table.enum_names.len() == 1);

	// Check ArrayHolder: array field Values has no NoOf member (C201)
	assert(table.structures.has_key("ArrayHolder"));
	StructuredType* arr_st = table.structures.get("ArrayHolder")!!;
	assert(arr_st.fields.len() == 1);
	Field f0 = arr_st.fields[0];
	assert(f0.name == "Values");
	assert(f0.is_array);
	assert(f0.length_field == "NoOfValues");

	// Ensure NoOfValues is NOT a member
	foreach (f : arr_st.fields)
	{
		assert(f.name != "NoOfValues");
	}

	// Check Composite
	assert(table.structures.has_key("Composite"));
	StructuredType* comp = table.structures.get("Composite")!!;
	assert(comp.fields.len() == 2);
	assert(comp.fields[0].name == "EnumField");
	assert(comp.fields[1].name == "Holder");

	// Check SampleEnum
	assert(table.enums.has_key("SampleEnum"));
	EnumeratedType* en = table.enums.get("SampleEnum")!!;
	assert(en.length_in_bits == 32);
	assert(en.values.len() == 2);
	assert(en.values[0].name == "Alpha" && en.values[0].value == 1);
	assert(en.values[1].name == "Beta" && en.values[1].value == 2);
}

fn void closure() @test
{
	// Test closure on mini.bsd
	char[] mini_bytes = file::load(mem, "tools/uagen/testdata/mini.bsd")!!;
	defer mem::free(mini_bytes.ptr);

	TypeTable mini_table;
	mini_table.init(mem);
	defer mini_table.free();

	parse_bsd(&mini_table, (String)mini_bytes)!!;

	String[1] mini_roots = { "Composite" };
	String[] mini_closure = compute_closure(&mini_table, mem, &mini_roots)!!;
	defer mem::free(mini_closure.ptr);

	// Mini closure contains ArrayHolder, Composite, SampleEnum (Int32 is builtin)
	assert(mini_closure.len == 3);
	assert(mini_closure[0] == "ArrayHolder");
	assert(mini_closure[1] == "Composite");
	assert(mini_closure[2] == "SampleEnum");

	// Test closure on full schema with roots.txt
	char[] full_bytes = file::load(mem, "schema/Opc.Ua.Types.bsd")!!;
	defer mem::free(full_bytes.ptr);

	TypeTable full_table;
	full_table.init(mem);
	defer full_table.free();

	parse_bsd(&full_table, (String)full_bytes)!!;

	String[] full_roots = load_roots(mem, "tools/uagen/roots.txt");
	defer
	{
		foreach (r : full_roots) mem::free(r.ptr);
		mem::free(full_roots.ptr);
	}

	String[] full_closure = compute_closure(&full_table, mem, full_roots)!!;
	defer mem::free(full_closure.ptr);

	assert(full_closure.len == 62);

	bool found_read_request = false;
	bool found_browse_result = false;
	bool found_endpoint_desc = false;
	bool found_argument = false;

	foreach (name : full_closure)
	{
		if (name == "ReadRequest") found_read_request = true;
		if (name == "BrowseResult") found_browse_result = true;
		if (name == "EndpointDescription") found_endpoint_desc = true;
		if (name == "Argument") found_argument = true;
	}

	assert(found_read_request);
	assert(found_browse_result);
	assert(found_endpoint_desc);
	assert(found_argument);
}

fn void unknown_type_is_error() @test
{
	String bad_bsd = `<opc:TypeDictionary xmlns:opc="http://opcfoundation.org/BinarySchema/">
		<opc:StructuredType Name="BadStruct" BaseType="ua:ExtensionObject">
			<opc:Field Name="BadField" TypeName="opc:NonExistentType" />
		</opc:StructuredType>
	</opc:TypeDictionary>`;

	TypeTable table;
	table.init(mem);
	defer table.free();

	parse_bsd(&table, bad_bsd)!!;

	String[1] roots = { "BadStruct" };
	assert(@fails(compute_closure(&table, mem, &roots), UAGEN_UNKNOWN_TYPE));

	// Error message must name both the unknown type and the field (C206)
	assert(last_error_msg.contains("NonExistentType"));
	assert(last_error_msg.contains("BadStruct"));
	assert(last_error_msg.contains("BadField"));
}

fn void switch_field_is_error() @test
{
	String switch_bsd = `<opc:TypeDictionary xmlns:opc="http://opcfoundation.org/BinarySchema/">
		<opc:StructuredType Name="SwitchStruct" BaseType="ua:ExtensionObject">
			<opc:Field Name="OptField" TypeName="opc:Int32" SwitchField="EncodingMask" />
		</opc:StructuredType>
	</opc:TypeDictionary>`;

	TypeTable table;
	table.init(mem);
	defer table.free();

	parse_bsd(&table, switch_bsd)!!;

	String[1] roots = { "SwitchStruct" };
	assert(@fails(compute_closure(&table, mem, &roots), UAGEN_UNSUPPORTED_CONSTRUCT));

	// Error message must name the switch field and struct (C202)
	assert(last_error_msg.contains("OptField"));
	assert(last_error_msg.contains("SwitchStruct"));
}
