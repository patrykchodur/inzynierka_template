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

The bitmask is then used in a [header field register info](#header-file-register-info) of this field.

In [the template protocol](#template-protocol) `data1` and `data2` fields need such extraction.
Their bitmasks are defined using the `#define` directive

```C
#define TEMPLATE_DATA1_MASK  0xFFF00000ull
#define TEMPLATE_DATA2_MASK  0x000FFFFFull
```





