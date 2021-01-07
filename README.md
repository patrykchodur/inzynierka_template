# Wireshark dissector template

This project is meant to be used as a template for writing own Wireshark dissector.
The resulting dissector will be a stand-alone plugin for Wireshark using `epan` API.

## Table of contents

- [Requrements](#requirements)
- [Template files](#template-files)
	- [Template protocol](#template-protocol)
- [Compiling a dissector](#compiling-a-dissector)
- [Installing a dissector](#installing-a-dissector)
- [Testing a dissector](#testing-a-dissector)
- [Writing a dissector](#writing-a-dissector)
	- [CMakeLists.txt file](#cmakeliststxt-file)
	- [Plugin source file](#plugin-source-file)
		- [Dissecting a packet](#dissecting-a-packet)
		- [Global scope](#global-scope)
			- [Include directives](#include-directives)
			- [Protocol handle](#protocol-handle)
			- [Header fields](#header-fields)
			- [Subtrees](#subtrees)
			- [Subfields arrays](#subfields-arrays)
			- [Bitmasks](#bitmasks)
			- [Custom display functions)(#custom-display-functions)
		- [void proto\_register\_template\_protocol() function](#void-proto_register_template_protocol-function)
			- [Protocol registration](#protocol-registration)
			- [Header fields registration](#header-fields-registration)
			- [Subtrees registration](#subtrees-registration)
		- [void proto\_reg\_handoff\_template\_protocol() function](#void-proto_reg_handoff_template_protocol-function)
		- [int dissect](#int-dissect)

## Requirements

The programmer needs a Wireshark source tree. This can be obtained from
[here](https://gitlab.com/wireshark/wireshark). The project was tested with `3.5.0` version of Wireshark.

There are no other requirements for writing the plugin aside from the ones of the Wireshark itself.
A decent text editor and `git` may be helpfull.

## Template files

Two disssector files are provided:
- `template.c` - which contains a simple dissector for template protocol. The file is designed to be
a guide for writing own dissector.
- `template_bare.c` - which contains a bare template that cannot be compiled. Designed as a starting point
for writing a new dissector.

Additionaly there is a `CMakeLists.txt` file that can be used to compile template dissector
or, with just a few modifications, used for own dissector.

### Template protocol

The template protocol, for which the `template.c` dissector if written, contains 2 main fields:
	- id field - 4 bytes
	- data field - 4 bytes that are split into 2 fields:
		- data1 - bits from 20 to 31 (mask `0xFFF00000`)
		- data2 - bits from 0 to 19 (mask `0x000FFFFF`)

The packet is sent using the `TCP` protocol on port `1234`.

This protocol will be used in [writing a dissector](#writing-a-dissector) chapter.

## Compiling a dissector

The dissector directory needs to be linked to `plugins/epan` directory of Wireshark source tree.
Resulting path must than be put into `CMakeListsCustom.txt` file as a `CUSTOM_PLUGIN_SRC_DIR`.
The `CMakeListsCustom.txt` file may not be present, just copy `CMakeListsCustom.txt.example` and delete
sample plugin paths.

To complile the plugin just run
```
mkdir build && cd build && cmake .. && cmake --build . --target *dissector name*
```
at the top of the Wireshark source tree.
A dissector name is the name specified inside the `CMakeLists.txt` file of the dissector.
For the template dissector the name is `template_dissector`.
Alternatively, the whole Wireshark project (including the dissector) can be compiled with
```
mkdir build && cd build && cmake .. && cmake --build . --target all
```

If the plugin is meant for a specific version of Wireshark `git checkout tags/wireshark-1.2.3`
can be used inside the source of Wireshark that is used for compiling the plugin, with `1.2.3`
replaced with the desired version.

## Installing a dissector

If the dissector is compiled separately, the resulting dissector (ie. `*.so` file) can be copied
into a propper `epan` directory of installed Wireshark. Otherwise the plugin is already installed.

The list of installed plugins, as well as the absolute path of the `epan` directory, can be found
at `Help->About Wireshark->Plugins` tab.

## Testing a dissector

The easiest way to test a dissector is to use `.pcap` files with captured packets.

If packets are not available, the user can generate a packet with the `hexedit` tool or some text editor.
Beware: most text editors add an extra new line at the end of the file.

The packet can than be sent using the `netcat` tool:
- `netcat -l -p 1234` to listen on port `1234`
- `cat testpacket | netcat -c localhost 1234` to send the content of testpacket file to `localhost` using `1234`
port. `-c` option stands for close at the `EOF`

To use `UDP` the `-u` option must be added. `-v` for verbose output may be helpfull as well.

## Writing a dissector

The `template.c`, `template_bare.c` and `CMakeLists.txt` files are provided to help writing own
dissectors. The dissector written in `template.c` is used to discuss the structure and the content
of a Wireshark dissector plugin.

To write a new plugin a programmer must write at least two files:
- `CMakeLists.txt`
- plugin source file

### CMakeLists.txt file

The `CMakeLists.txt` file for a new dissector can be based on the file provided with this repository.
It is based on the one from the `gryphon` plugin. Most of it's content does not have
to be changed, except for these lines:
- `set(PLUGIN_NAME template_dissector)` - specifies the dissector name.
- `set_module_info(${PLUGIN_NAME} 0 0 1 0)` - sets the version of the dissector. The numbers are:
	- version major
	- version minor
	- version micro
	- version extra
- `set(DISSECTOR_SRC template.c)` - the list of implementation files of the project (no header files)

This file will be included during build process by the `cmake` tool. The folder containing `CMakeLists.txt`
must be included in `CMakeListsCustom.txt` (see [Compiling a dissector](#compiling-a-dissector)).

### Plugin source file

Plugin can be written in just one `.c` file. It's structure will be discussed in this section.
`template.c` dissector is used as a reference. All `template` occurences should be replaced with a desired name.

The purpose of used `static` specifiers is:
- in global scope - to hide names from other source files
- in functions - to preserve a variable from being deleted after leaving the function, as Wireshark is not
making a copy of it.

#### Dissecting a packet

The process of dissecting a packet is done by building the packet tree. The tree nodes are packet fields.
If a packet field consists of other fields, they are it's child nodes. A fields with it's child nodes is called
a subtree. The actual process of building the tree is discussed at later.

Every dissector needs at least 3 functions:
- `int dissect()` - for the packed dissection
- `void proto_register_template_protocol()` - used to register the dissector, it's fields and trees.
- `void proto_reg_handoff_template_protocol()` - used to "handoff" the protocol (ie. tell the Wireshark
which packets should be sent to the dissector).

These functions, as well as a global scope, will be discussed in separate subsections.

Names of the `register` and `handoff` routines must have `proto_register_*` and `proto_reg_handoff_` form.
This is because the code to call these functions is generated by the Wireshark
during the compile time. All other declared names are arbitrary.

#### Global scope

The global scope for a dissector, apart from mentioned earlier functions, must contain at least the following:
- [include directives](#include-directives)
- [protocol handle declaration](#protocol-handle)
- [header fields declarations](#header-fields)
- [subtrees declarations](#subtrees)

Depending of the protocol nature it may be required to declare:
- [subfields arrays](#subfields-arrays)
- [bitmasks](#bitmasks)
- [custom display functions](#custom-display-functions)

##### Include directives

The source code of a new dissector must include at least these files:
- `"config.h"` - generated during the compilation of a plugin
- `<epan/packet.h>` - header file for `epan` dissectors library

Using custom libraries may require modifying the `CMakeLists.txt` file, but the C Standard Library
should be accessible without any problems.

##### Protocol handle
The protocol handle is used for registration of a new protocol.
It is the first item to be added to the protocol tree (discussed later).

```C
static int proto_template_protocol = -1;
```

##### Header fields

The header fields are used to describe the protocol fields. Their handles are declared in the global scope.
A separate header field must be used for every protocol field, even for fields that consist of other fields.
[The template protocol](#template-protocol) contains 4 fields:
- `id` field
- `data` field
- `data1` field
- `data2` field

The declaration of header field handles for this protocol is as follows:

```C
static int hf_template_id = -1;
static int hf_template_data = -1;
static int hf_template_data1 = -1;
static int hf_template_data2 = -1;
```

##### Subtrees

Subtree is a protocol element with it's child nodes and their subrees.
To simplify, a subtree is every element that can be expanded in GUI.
Every subtree of the protocol has to be registered. This applies to the protocol
tree itself as it is considered to be a subtree for the lower level protocol (`TCP` for 
[the template protocol](#template-protocol)).

[The template protocol](#template-protocol) has two subtrees:
- the protocol itself
- data section

Subtree handles are declared as values of `gint` type. The declaration of
[the template protocol](#template-protocol) subtrees is:

```C
static gint ett_template = -1;
static gint ett_template_data = -1;
```

##### Subfields arrays

If a protocol field consists of other fields, it's elements must be specified in a `NULL`
terminated subfields array. The array holds [header fields](#header-fields) pointers
and is used as a parameter for `proto_tree_add_bitmask*` functions family.

[The template protocol's](#template-protocol) `data` segment is an example of such field, as
it contains `data1` and `data2`. Therefore it's array is declared as follows:

```C
static int * data_fields[] = {
	&hf_template_data1,
	&hf_template_data2,
	NULL
};
```

##### Bitmasks

Bitmask are used to extract the data from a value of a field, if only some
bits of the number should be used. The two most common cases are:
- the field does not use all it's bits (e.g. a number is sent in a 4 bytes field,
but only 30 bits are used).
- the field is a subfield.

The bitmask is then used in a [header field register info](#header-field-register-info) of this field.

In [the template protocol](#template-protocol) `data1` and `data2` fields need such extraction.
Their bitmasks are defined using the `#define` directive

```C
#define TEMPLATE_DATA1_MASK  0xFFF00000ull
#define TEMPLATE_DATA2_MASK  0x000FFFFFull
```

##### Custom display functions


#### void proto\_register\_template\_protocol() function

The `void proto_register_template_protocol()` function is used to register
the [protocol](#protocol-registration), it's [fields](#header-fields-registration) and
[subtrees](#subtrees-registration).
It contains the protocol fields definitions as well.

##### Protocol registration

Registration of the protocol is done with a call to `int proto_register_protocol()` function. The function
takes 3 `NULL` terminated strings:
- full name
- short name
- filter name

The full name and short name are used in the Wireshark GUI. The filter name is used for filtering protocols
and accessing protocol fields. Filter name should be lowercase.

The return value of this function call should be assigned to the declared earlier
[protocol handle](#protocol-handle).

[The template protocol](#template-protocol) call to this function:

```C
proto_template_protocol = proto_register_protocol (
		"Template Protocol",
		"Template",
		"template"
	);
```

##### Header fields registration

The protocol fields are defined using an array of type `hf_register_info`. The array is than bound
to the protocol by `void proto_register_field_array()` function.

The `hf_register_info` struct consists of the [header field handle](#header-fields) pointer and `header_field_info`
struct, which is defined as follows:

```C
struct header_field_info {
    const char      *name;
    const char      *abbrev;
    enum ftenum     type;
    int             display;
    const void      *strings;
    guint64         bitmask;
    const char      *blurb;
    .....
};
```

Full description of its fields is provided in the `README.dissector` file from `doc` directory in Wireshark
source code. A brief description of each parameter:
- `name` variable should be filled with a short name of the protocol field.
- `abbrev` is used to provide a filter name for the protocol field. The filter name should be a dot separated
path of the protocol field. Filter names for [the template protocol](#template-protocol) are:
	- `template.id`
	- `template.data`
	- `template.data.data1`
	- `template.data.data2`
- `type` tells the Wireshark what to do with the field. The types are prefixed with `FT_`. Some examples are:
	- `FT_UINT32` - 32 bits unsigned int
	- `FT_INT24` - 24 bits signed int
	- `FT_FLOAT` - 32 bits float
	- `FT_STRINGZ` - `NULL` (Zero) terminated string
- `display` is used to specify the way of displaying a field. Available options depend on the `type`,
for example integer types can specify base for their notation (e.g. `BASE_DEC`), but two options are special:
	- `BASE_NONE` is used for fields that have only one way of displaying
	- `BASE_CUSTOM` is used if a custom display function is provided
- `strings` field is overloaded and it's meaning depend on the `display` parameter. If no content is needed `NULL`
should be used. The field is usually used to provide:
	- `value_string` array, which is used to translate integer value to a string that is used to display a field.
It is helpfull for enum type fields, where specific codes have some meanings.
	- [custom display function](#custom-display-functions) that takes `gchar` pointer and the
field value. The function pointer is passed using a `CF_FUNC()` macro.
- [bitmask](#bitmasks) is used to provide a field's bitmask. If none is needed, `0` constant should be used.
- `blurb` is a field description

Filled `hf_register_info` array is be passed to the `void proto_register_field_array()` function,
which takes [the protocol handle](#protocol-handle), the just created array and it's length.

The `hf_register_info` array and it's registration for [the template protocol](#template-protocol):

```C
static hf_register_info hf[] = {
	/* TEMPLATE FIELDS */
	{ &hf_template_id, 
		{ "Template id", DISSECTOR_FILTER_NAME ".id", 
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Some id for template protocol", HFILL }
	},
	{ &hf_template_data,
		{ "Data", DISSECTOR_FILTER_NAME ".data",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Data section of template protocol", HFILL }
	},

	/* DATA_FIELDS */
	{ &hf_template_data1,
		{ "Data 1", DISSECTOR_FILTER_NAME ".data.data1",
		  FT_UINT32, BASE_HEX, NULL, TEMPLATE_DATA1_MASK,
		  "Data 1 from template protocol", HFILL }
	},
	{ &hf_template_data2,
		{ "Data 2", DISSECTOR_FILTER_NAME ".data.data2",
		  FT_UINT32, BASE_CUSTOM, CF_FUNC(&display_template_data2), TEMPLATE_DATA2_MASK,
		  "Data 2 from template protocol", HFILL }
	}
};

proto_register_field_array(proto_template_protocol, hf, array_length(hf));
```

##### Subtrees registration

The [subtrees](#subtrees) are registred using the `void proto_register_subtree_array()` function,
which takes an subtree pointer array and it's length.

```C
static gint *ett[] = {
	&ett_template,
	&ett_template_data
};

proto_register_subtree_array(ett, array_length(ett));
```

#### void proto\_reg\_handoff\_template\_protocol() function

The handoff function is used to create a dissector handle and to add the protocol dissector to the dissector table.

The creation of the dissector handle is done with a call to `dissector_handle_t create_dissector_handle()`.
It takes the [dissect](#int-dissect) function and a [protocol handle](#protocol-handle).

The dissector table is used to find a suitable dissector for the packet. Apart from "Custom tables", three
table types are used:
- "Heuristic tables" - used for heuristic dissectors. The packet is passed to the dissector, which decide whether
to dissect the packet or not. If the packet is rejected, the next dissector in table is used.
- "Integer tables" - a lower level dissector field and it's expected value is provided. If these values match,
it means the dissector should be used. Functions used to add a dissector to these tables are:
	- `void dissector_add_uint()`
	- `void dissector_add_uint_range()`
- "String tables" - same as "Integer tables" but strings are compared. The function used to register a dissector
in these tables is `void dissector_add_string()`.

[The template protocol](#template-protocol) is registered in the "Integer tables", as it compares the `"tcp.port"`
value to `1234` protocol number.

The definition of the `void proto_reg_handoff_template_protocol()` function:

```C
void proto_reg_handoff_template_protocol (void)
{
	static dissector_handle_t proto_handle;

	proto_handle = create_dissector_handle(dissect, proto_template_protocol);
	dissector_add_uint(HIGHER_LEVEL_PROTOCOL ".port", PORT_NO, proto_handle);
}
```

#### int dissect() function

