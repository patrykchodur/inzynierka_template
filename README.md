# Wireshark dissector template

This project is meant to be used as guide for writing a Wireshark dissector.
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
			- [Custom display functions](#custom-display-functions)
		- [Register routine](#register-routine)
			- [Protocol registration](#protocol-registration)
			- [Header fields registration](#header-fields-registration)
			- [Subtrees registration](#subtrees-registration)
		- [Handoff routine](#handoff-routine)
		- [Dissect function](#dissect-function)

## Requirements

The Wireshark source code is required to build a dissector. It can be obtained from
[here](https://gitlab.com/wireshark/wireshark). The project was tested with the `3.5.0`
version of Wireshark.

There are no other requirements for writing the plugin, aside from the requirements of
the Wireshark itself. A decent text editor and the `git` may be helpfull.

## Template files

Two disssector files are provided for this guide:
- `template.c` - which contains a simple dissector for a template protocol. The file is
  designed to be an expample of a dissector that can be compiled and tested.
- `template_bare.c` - which contains a bare template that cannot be compiled. Designed as
  a starting point for writing a new dissector.

Additionaly, there is a `CMakeLists.txt` file that can be used to compile the template
dissector, or with just a few modifications used for an own dissector.

### Template protocol

The template protocol, for which the `template.c` dissector is written, contains 2 main fields:
- id field - 4 bytes
- data field - 4 bytes that are split into 2 fields:
	- data1 - bits from 20 to 31 (mask `0xFFF00000`).
	- data2 - bits from 0 to 19 (mask `0x000FFFFF`). When displayed, the value of `data2` field
	  should be increased by 2.

The packet is sent using the `TCP` protocol on port `1234`.

This protocol will be used in the [writing a dissector](#writing-a-dissector) chapter.

## Compiling a dissector

The directory containing a dissectors source files needs to be linked to the `plugins/epan`
directory of the Wireshark source tree. Resulting path must than be put into
the `CMakeListsCustom.txt` file as a `CUSTOM_PLUGIN_SRC_DIR`. The `CMakeListsCustom.txt` file
may not be present. If so, the `CMakeListsCustom.txt.example` file can be copied. Sample paths
from the example file should be removed.

The plugin can be compiled by using the following command at the top of the Wireshark source
tree.

```sh
mkdir build && cd build && cmake .. && cmake --build . --target <dissector name>
```

A dissector name is the name specified inside the `CMakeLists.txt` file for the dissector.
For the template dissector the name is `template_dissector`. Alternatively, the whole
Wireshark project (including the dissector) can be compiled using:

```sh
mkdir build && cd build && cmake .. && cmake --build . --target all
```

If the plugin is meant for a specific version of Wireshark, `git checkout tags/wireshark-1.2.3`
can be used inside the Wireshark source copy that is used for compiling the plugin, with `1.2.3`
replaced by the desired version.

## Installing a dissector

If the dissector is compiled separately, the resulting dissector (ie. `*.so` file) can be copied
into a propper `epan` directory of an installed Wireshark. Otherwise the plugin is already
installed.

The list of installed plugins, as well as the absolute path of the `epan` directory, can be
found at `Help->About Wireshark->Plugins` tab.

## Testing a dissector

The easiest way to test a dissector is to use `.pcap` files containing captured packets.
If packets are not available, the user can generate a packet with the `hexedit` tool, or some
text editor. **Beware: most text editors add an extra new line at the end of the file.**

The packet can than be sent using the `netcat` tool:
- `netcat -l -p 1234` to listen on port `1234`
- `cat <test_packet> | netcat -c localhost 1234` to send the content of testpacket file to
  `localhost` using `1234` port. `-c` option stands for "Close the connection at the `EOF`".

To use `UDP`, the `-u` option must be added. `-v` for verbose output may be helpfull as well.

## Writing a dissector

The `template.c`, `template_bare.c` and `CMakeLists.txt` files are provided to help writing own
dissectors. The dissector written in `template.c` is used to discuss the structure, and
the content, of a Wireshark dissector plugin.

To write a new plugin, a programmer must write at least two files:
- [CMakeLists.txt](#cmakeliststxt-file)
- a [plugin source file](#plugin-source-file)

### CMakeLists.txt file

The `CMakeLists.txt` file for a new dissector can be based on the file provided with this
repository. It is based on the one from the `gryphon` plugin. Most of it's content does not
have to be changed, except for these lines:
- `set(PLUGIN_NAME template_dissector)` - specifies the dissector name.
- `set_module_info(${PLUGIN_NAME} 0 0 1 0)` - sets the version of the dissector.
  The numbers are:
	- version major
	- version minor
	- version micro
	- version extra
- `set(DISSECTOR_SRC template.c)` - the list of implementation files of the project
  (no header files)

This file will be included during build process by the `cmake` tool. The directory containing
a `CMakeLists.txt` must be included in `CMakeListsCustom.txt`
(see [compiling a dissector](#compiling-a-dissector)).

### Plugin source file

A plugin can be written in just one `.c` file. Its structure will be discussed in this section.
`template.c` dissector is used as a reference. All "template" occurences should be replaced
with a desired name.

The purpose of all used `static` specifiers is:
- in a global scope - to hide the names from other source files
- in functions - to preserve a variable from being deleted after leaving the function,
  as the Wireshark is not making a copy of it.

#### Dissecting a packet

The process of dissecting a packet is done by building the packet tree. The tree nodes are
packet fields. If a packet field consists of other fields, they are it's child nodes.
A fields with it's child nodes is called a subtree. The actual process of building the tree
is discussed [later](#dissect-function).

Every dissector needs at least 3 functions:
- [register routine](#register-routine) - used to register the dissector, its fields
  and subtrees.
- [handoff routine](#handoff-routine) - used to "handoff" the protocol (ie. tell the Wireshark
  which packets should be sent to the dissector).
- [dissect function](#dissect-function) - the funtion that dissect the packet.

These functions, as well as a [global scope](#global-scope), will be discussed in separate
subsections.

#### Global scope

The global scope for a dissector, apart from mentioned earlier functions, must contain at
least the following:
- [include directives](#include-directives)
- [protocol handle declaration](#protocol-handle)
- [header fields declarations](#header-fields)
- [subtrees declarations](#subtrees)

Depending of the protocol nature, it may be required to declare:
- [subfields arrays](#subfields-arrays)
- [bitmasks](#bitmasks)
- [custom display functions](#custom-display-functions)

##### Include directives

The source code of a new dissector must include at least these files:
- `"config.h"` - generated during the compilation of a plugin.
- `<epan/packet.h>` - header file for the `epan` dissectors library.

Using custom libraries may require modifying the `CMakeLists.txt` file, but the *C Standard
Library* should be accessible without any problems.

##### Protocol handle
The protocol handle is used for the registration of a new protocol. It is the first item
to be added to the protocol tree (discussed [later](#dissect-function)).

```C
static int proto_template_protocol = -1;
```

##### Header fields

The header fields are used to describe the protocols fields. Their handles are declared in
the global scope. A separate header field must be declared for every protocol field, even
for fields that consist of other fields.

The [template protocol](#template-protocol) contains 4 fields:
- `id` field
- `data` field
- `data1` field
- `data2` field

The declaration of all header field handles:

```C
static int hf_template_id = -1;
static int hf_template_data = -1;
static int hf_template_data1 = -1;
static int hf_template_data2 = -1;
```

##### Subtrees

Subtree is a protocol element along with it's child elements and their subtrees.
To simplify, a subtree is every element that can be expanded in GUI. Every subtree of
the protocol has to be registered. This applies to the whole protocol tree as well,
as it is considered to be a subtree for the lower level protocol (`TCP` for 
the [template protocol](#template-protocol)).

The [template protocol](#template-protocol) has two subtrees:
- the protocol itself
- the data section

Subtree handles are declared as values of `gint` type. The declaration of
the [template protocol](#template-protocol) subtrees:

```C
static gint ett_template = -1;
static gint ett_template_data = -1;
```

##### Subfields arrays

If a protocol field consists of other fields, its elements must be specified in a `NULL`
terminated subfields array. The array holds [header fields](#header-fields) pointers
and is used as a parameter for `proto_tree_add_bitmask*` functions family.

The [template protocol's](#template-protocol) `data` segment is an example of such field, as
it contains `data1` and `data2`. Therefore, its array is declared as follows:

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

The result of the extraction is then right-shifted according to a position of the first true
bit of the mask.

The bitmask is used in a [header field register info](#header-fields-registration) of the field.

In the [template protocol](#template-protocol), `data1` and `data2` fields need such extraction.
Their bitmasks are defined using the `#define` directive:

```C
#define TEMPLATE_DATA1_MASK  0xFFF00000ull
#define TEMPLATE_DATA2_MASK  0x000FFFFFull
```

##### Custom display functions

Custom display functions are used if built-in options are not sufficient. An exapmle of such
situation may be the need to add a constant value to the field. A custom display function
takes `gchar` pointer and the value. The value is provided as a `guint32` (for fields using
32 bits and less) or `guint64` (more than 32 bits) value.

The custom display function is written for the [template protocols](#template-protocol)
field `data2`, as it's value should be increased by 2.

```C
void display_template_data2(gchar *str, guint32 val) {
	snprintf(str, ITEM_LABEL_LENGTH, "%" G_GUINT32_FORMAT, val + 2);
}
```

#### Register routine

The register routine is used for:
- the [protocol registration](#protocol-registration)
- [header fields registration](#header-fields-registration)
- [subtrees registration](#subtrees-registration).

It contains the protocol fields definitions as well.

The register function name should be prefixed with `proto_register_`. The reason is that during
the compilation of a dissector a special function to call the register routine, as well as
the handoff routine, is generated.

The function should not take, nor return, any arguments.

##### Protocol registration

The registration of a protocol is done with a call to `int proto_register_protocol()` function.
The function takes 3 `NULL` terminated strings:
- a full name
- a short name
- a filter name

The full name and the short name are used in the Wireshark GUI. The filter name is used
for filtering protocols and accessing protocol fields. The filter name should be lowercase.

The return value of this function call should be assigned to the declared earlier
[protocol handle](#protocol-handle).

The [template protocol](#template-protocol) call to this function:

```C
proto_template_protocol = proto_register_protocol (
		"Template Protocol",
		"Template",
		"template"
	);
```

##### Header fields registration

The protocol fields are defined using an array of the `hf_register_info` type. The array is than
bound to the protocol by `void proto_register_field_array()` function.

The `hf_register_info` struct consists of the [header field handle](#header-fields) pointer
and a `header_field_info` struct, which is defined as follows:

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

The full description of its fields is provided in the `README.dissector` file from the `doc`
directory in the Wireshark source code. A brief description of each parameter:
- `name` variable should be filled with a short name of the protocol field.
- `abbrev` is used to provide a filter name for the protocol field. The filter name should be
  a dot separated path of the protocol field. Filter names for
  the [template protocol](#template-protocol) are:
	- `template.id`
	- `template.data`
	- `template.data.data1`
	- `template.data.data2`
- `type` tells the Wireshark what to do with a field. The types are prefixed with `FT_`.
  Some examples are:
	- `FT_UINT32` - 32 bits unsigned int
	- `FT_INT24` - 24 bits signed int
	- `FT_FLOAT` - 32 bits float
	- `FT_STRINGZ` - `NULL` (Zero) terminated string
- `display` is used to specify the way of displaying a field. Available options depend on
  the `type`. For example, for the integer types the base of their notation can be specified
  (e.g. `BASE_DEC`). Two options are special:
	- `BASE_NONE` - used for fields that have only one way of displaying.
	- `BASE_CUSTOM` - used if a custom display function is provided.
- `strings` field is overloaded and its meaning depend on the `display` parameter.
  If no content is needed, the `NULL` value should be used. The field is usually used to
  provide:
	- a `value_string` array, which is used to translate integer values to strings, which are
	  than used to display a field. It is usually helpfull for enum type fields, where
	  specific codes have some meanings.
	- a [custom display function](#custom-display-functions) that takes a `gchar` pointer and
	  the fields value. The function pointer is passed using a `CF_FUNC()` macro.
- [bitmask](#bitmasks) is used to provide a fields bitmask. If none is needed, the `0`
  constant value should be used.
- `blurb` is a brief field description
- the rest of the struct are internal fields. They should be filled using `H_FILL` macro.

Filled `hf_register_info` array is passed to the `void proto_register_field_array()` function,
which takes the [protocol handle](#protocol-handle), the just created array and it's length.

The `hf_register_info` array and it's registration for
the [template protocol](#template-protocol):

```C
static hf_register_info hf[] = {
	/* TEMPLATE FIELDS */
	{ &hf_template_id, 
		{ "Template id", "template.id", 
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Some id for template protocol", HFILL }
	},
	{ &hf_template_data,
		{ "Data", "template.data",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  "Data section of template protocol", HFILL }
	},

	/* DATA_FIELDS */
	{ &hf_template_data1,
		{ "Data 1", "template.data.data1",
		  FT_UINT32, BASE_HEX, NULL, TEMPLATE_DATA1_MASK,
		  "Data 1 from template protocol", HFILL }
	},
	{ &hf_template_data2,
		{ "Data 2", "template.data.data2",
		  FT_UINT32, BASE_CUSTOM, CF_FUNC(&display_template_data2), TEMPLATE_DATA2_MASK,
		  "Data 2 from template protocol", HFILL }
	}
};

proto_register_field_array(proto_template_protocol, hf, array_length(hf));
```

##### Subtrees registration

The [subtrees](#subtrees) are registred using the `void proto_register_subtree_array()`
function, which takes an subtree pointer array and its length.

```C
static gint *ett[] = {
	&ett_template,
	&ett_template_data
};

proto_register_subtree_array(ett, array_length(ett));
```

#### Handoff routine

The handoff routine is used to create a dissector handle and to add the protocols dissector
to the dissectors tables.

The name of this function should begin with `proto_reg_handoff_` for the same reason as
the [register routine](#register-routine).

The creation of the dissector handle is done with a call to
the `dissector_handle_t create_dissector_handle()` function.
It takes the [dissect function](#dissect-function) and a [protocol handle](#protocol-handle)
as the arguments.

The dissector tables are used to find a suitable dissector for the packet. Apart from
"Custom tables", three table types are used:
- "Heuristic tables" - used for heuristic dissectors. The packet is passed to a dissector,
  which decides whether to dissect the packet or not. If the packet is rejected, the next
  dissector in the table is used.
- "Integer tables" - a lower level dissector field and its expected value are provided.
  If these values match, it means a dissector should be used. Functions used to add
  a dissector to these tables are:
	- `void dissector_add_uint()`
	- `void dissector_add_uint_range()`
- "String tables" - same as "Integer tables" but strings are compared. The function used
  to register a dissector in these tables is `void dissector_add_string()`.

The [template protocol](#template-protocol) is registered in the "Integer tables", as it
compares the `"tcp.port"` value to the `1234` port number.

The definition of the `void proto_reg_handoff_template_protocol()` function:

```C
void proto_reg_handoff_template_protocol (void)
{
	static dissector_handle_t proto_handle;

	proto_handle = create_dissector_handle(dissect, proto_template_protocol);
	dissector_add_uint("tcp.port", 1234, proto_handle);
}
```

#### Dissect function

The dissect function is used to build a protocol tree and to set the packet info.
It takes 4 arguments and returns an `int` indicating a number of consumed bytes.
The arguments are:
- a packet buffer - passed as a pointer to an object of type `tvbuff_t`. Its structure is
  not introduced to the programmer. Any operations should be performed using provided by
  the Wireshark functions. Basic operations, like reading from the buffer or getting its
  length, are done using `tvb_*` functions.
- a packet info - a pointer to a `packet_info`. The pointer is used with `col_` functions to
  set columns in the Wiresharks GUI, particurarly *Protocol* and *Info* columns.
- a protocol tree - a pointer to a `proto_tree` object. It is a pointer to a lower level
  dissector tree that will be used as a root for the to-be-created protocol tree.
- a data void pointer - for advanced dissectors. Not used here, thus the *unused* attribute
  will follow its declaration.

```C
static int dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
```

Usually a dissect function can be split into 3 parts:
- [basic checks](#basic-checks)
- [setting packet info](#setting-packet-info)
- [building a packet tree](#building-a-packet-tree)

##### Basic checks

If the packets length is constant, the first thing to do at the beginning of a dissector,
is to check the passed packets length. If the length is not appropriate, there is no point
in dissecting the packet. The check can be done using a `guint tvb_captured_length()` function.

Depending on the protocol, other checks can be performed. For example, if the protocol has
4 special codes sent on a byte, a value not matching any code may be a sign of an inappropriate
packet. The code value could be retrived using the `guint8 tvb_get_guint8()` function.

If the checks fail, a value `0` should be returned, indicating no bytes were consumed.

```C
if (tvb_captured_length(tvb) != 8)
	return 0;
```

##### Setting packet info

The next thing to do, in a dissect function, is to set columns content. There are 2 columns
to fill: *Protocol* and *Info*.

Columns are manipulated using `col_` functions. To clear the column, a call to
the `void col_clear()` function should be used. Only *Info* column should be cleared -
the *Protocol* column does not require it. There are 2 functions used to fill a column
with a string. The choise should depent on the lifetime of a string:
- `void col_set_str()` - for static strings.
- `void col_add_str()` - for automatic (located on the stack) strings. The string is copied.

For convenience, the `void col_add_fstr()` function is provided, taking a format string as
an argument.

The *Protocol* column should contain a short name of the protocol.
It's usually a static string, saved in read only memory, that does not change.

The *Info* on the other hand, is used to distinguish the packet from other packets,
so it should use some of the packets data. `tvb_get_*` functions can be used to retrive it.

```C
guint32 template_id = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN);

col_set_str(pinfo->cinfo, COL_PROTOCOL, "Template");
col_clear(pinfo->cinfo, COL_INFO);
col_add_fstr(pinfo->cinfo, COL_INFO, "id: %" G_GUINT32_FORMAT, template_id);
```

##### Building a packet tree

To add an item to the packet tree, the `proto_item* proto_tree_add_item()` function is
usually used. It takes the tree, to which an item is added, an item handle (usually
a [header field](#header-fields) or a [protocol](#protocol-handle) handle), a buffer pointer,
an offset at which the item is located in the buffer, a length of the item in bytes,
and its encoding (usually either `ENC_LITTLE_ENDIAN`, `ENC_BIG_ENDIAN` or `ENC_NA` - Not
Available).

```C
proto_tree_add_item(top_tree, hf_template_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
```

It is a good idea to keep the offset in a variable of type `guint` and increase it by the size
of a just added field. That way, the programmer does not need to keep track of the offset.

```C
offset += 4;
```

To add a protocol field that has subfields, the `proto_item* proto_tree_add_bitmask()` function
is used. 2 additional arguments need to be provided between the [header field](#header-field)
and the encoding: an [ett handle](#subtrees) and a [subfield array](#subfield-arrays).
The subtree is implicitly created.

```C
proto_tree_add_bitmask(top_tree, tvb, offset, hf_template_data, ett_template_data, data_fields, ENC_LITTLE_ENDIAN);
offset += 4;
```

To explicilty add a subtree, an item returned from previous functions is used together with
the [ett handle](#subtrees) of the new tree. The function to call is
`proto_tree* proto_item_add_subtree()`.

A tree for the whole protocol needs to be added that way. A tree item representing the
protocol itself is added to the lower protocol tree, and than a subtree is created. When
adding a protocol, a special length value `-1` can be used.

```C
proto_item *top_tree_item = proto_tree_add_item(tree, proto_template_protocol, tvb, 0, -1, ENC_NA);
proto_tree *top_tree = proto_item_add_subtree(top_tree_item, ett_template);
```

Of course there are other, more complex functions designed to add objects to a tree.
An example of such function may be the `proto_item* proto_tree_add_string()` function.
They are described in the *README.dissector* file in the *doc* directory of the Wireshark
source tree.

At the end of the process, the offset should be returned from the function, indicating number
of consumed bytes. It should be equal to the total length of the packet.

