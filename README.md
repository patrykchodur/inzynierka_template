# Wireshark dissector template

This project is meant to be used as a template for writing own Wireshark dissector.
The resulting dissector will be a stand-alone plugin for Wireshark using `epan` API.

## Requirements

The programmer needs a Wireshark source tree. This can be obtained from
[here](https://gitlab.com/wireshark/wireshark). The project was tested with `3.5.0` version of Wireshark.

There are no other requirements for writing the plugin aside from the ones of the Wireshark itself.
A decent text editor and `git` may be helpfull.

## Template files

Two disssector files are provided as a guide:
- `template.c` - which contains a simple dissector for template protocol designed to be
a starting point for writing own dissector. The protocol contains 2 fields:
	- id field - 4 bytes
	- data field - 4 bytes that are split into:
		- data1 - mask `0xFFF00000`
		- data2 - mask `0x000FFFFF`
- `template_bare.c` - which contains a bare template that cannot be compiled

Additionaly there is a `CMakeLists.txt` file that can be used to compile template dissector
or, with just a few modifications, used for own dissector.

## Compiling a dissector

The dissector directory needs to be linked to `plugins/epan` directory of Wireshark source tree.
Resulting path must than be put into `CMakeListsCustom.txt` file as a `CUSTOM_PLUGIN_SRC_DIR`.
The `CMakeListsCustom.txt` file may not be present, just copy `CMakeListsCustom.txt.example` and delete
sample plugin paths.

To complile the sample plugin just run
```
mkdir build && cd build && cmake .. && cmake --build . --target *dissector name*
```
at the top of Wiresharks source tree.
A dissector name is the name specified inside the `CMakeLists.txt` file of the dissector.
For the template dissector it is `template_dissector`.
Alternatively, the whole Wireshark project (including the dissector) can be comiled with
```
mkdir build && cd build && cmake .. && cmake --build . --target all
```

If the plugin is meant for a specific version of Wireshark `git checkout tags/wireshark-1.2.3`
can be used inside the source of Wireshark that is used for compiling the plugin.

## Installing a dissector

If the dissector is compiled separately, the resulting dissector (ie. `*.so`) can be copied
into a propper `plugins/epan` directory of installed Wireshark. Otherwise the plugin is already installed.

The list of installed plugins can be found at `Help->About->Plugins` tab.

## Testing a dissector

The easiest way to test a dissector is to use `.pcap` files with captured packets.

If packets are not available the user can generate a packet with `hexedit` tool or some text editor.
Beware: most text editors add an extra new line at the end of the file.
The packet can than be sent using the `netcat` tool:
- `netcat -l -p 1234` to listen on port `1234`
- `cat testpacket | netcat -c localhost 1234` to send the content of testpacket file to `localhost` using `1234`
port. `-c` option stands for close at the `EOF`
To use `UDP` the `-u` option must be added. `-v` for verbose output may be helpfull as well

## Writing a dissector
