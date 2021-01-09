#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#include <assert.h>

// Template Protocol:
// id (4 bytes) data (4 bytes)
//     data:
//     data1 (12 bits) data2 (20 bits)


// PROTOCOL HANDLE
static int proto_template_protocol = -1;


// PROTOCOL FIELDS HANDLES
static int hf_template_id = -1;
static int hf_template_data = -1;


// DATA
static int hf_template_data1 = -1;
static int hf_template_data2 = -1;

#define TEMPLATE_DATA1_MASK               0xFFF00000ull
#define TEMPLATE_DATA2_MASK               0x000FFFFFull

static int * data_fields[] = {
	&hf_template_data1,
	&hf_template_data2,
	NULL
};


// CUSTOM DISPLAY FUNCTIONS (for bitfields)
void display_template_data2(gchar *str, guint32 val) {
	snprintf(str, ITEM_LABEL_LENGTH, "%" G_GUINT32_FORMAT, val + 2);
}

// TREES HANDLES
static gint ett_template = -1;
static gint ett_template_data = -1;

static int dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (tvb_captured_length(tvb) == 8)
		return 0;

	// getting the basic info that will be used while unpacking the data
	guint32 template_id = tvb_get_guint32(tvb, 0, ENC_LITTLE_ENDIAN);

	// Preparing column info (upper window)
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Template");
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "id: %" G_GUINT32_FORMAT, template_id);

	// Registering top tree
	proto_item *top_tree_item = proto_tree_add_item(tree, proto_template_protocol, tvb, 0, -1, ENC_NA);
	proto_tree *top_tree = proto_item_add_subtree(top_tree_item, ett_template);


	/* CONSUMING THE DATA */

	guint offset = 0;

	// id
	proto_tree_add_item(
			top_tree,
			hf_template_id,
			tvb,
			offset,
			4,
			ENC_LITTLE_ENDIAN
		);
	offset += 4;

	// data
	proto_tree_add_bitmask(
			top_tree,
			tvb,
			offset,
			hf_template_data,
			ett_template_data,
			data_fields,
			ENC_LITTLE_ENDIAN
		);
	offset += 4;

	// we should have consumed all the data
	assert(tvb_captured_length(tvb) == offset);
	return tvb_captured_length(tvb);
}

void proto_register_template_protocol (void)
{
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
		},
	};

	// trees handles list
	static gint *ett[] = {
		&ett_template,
		&ett_template_data
	};

	// register protocol
	proto_template_protocol = proto_register_protocol (
			"Template Protocol",
			"Template",
			 "template"
		);

	proto_register_field_array(proto_template_protocol, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_template_protocol (void)
{
	static dissector_handle_t proto_handle;

	proto_handle = create_dissector_handle(dissect, proto_template_protocol);
	dissector_add_uint("tcp.port", 1234, proto_handle);
}
