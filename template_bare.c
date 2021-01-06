#include "config.h"
#include <epan/packet.h>


// PROTOCOL HANDLE
static int proto_template_protocol = -1;

// TREES HANDLES
static gint ett_template = -1;

static int dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *top_tree_item;
	proto_tree *top_tree;

	guint offset = 0;

	// Preparing column info (upper window)
	col_set_str(pinfo->cinfo, COL_PROTOCOL, /* dissector name */ );
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, /* info column */ );

	// Registering top tree
	top_tree_item = proto_tree_add_item(tree, proto_template_protocol, tvb, 0, -1, ENC_NA);
	top_tree = proto_item_add_subtree(top_tree_item, ett_template);


	return tvb_captured_length(tvb);
}

void proto_register_template_protocol (void)
{
	static hf_register_info hf[] = {
		/* HEADER FILEDS */
	};

	// trees handles list
	static gint *ett[] = {
		&ett_template,
	};

	// register protocol
	proto_template_protocol = proto_register_protocol (
			/* name        */,
			/* short name  */,
			/* filter_name */
		);

	proto_register_field_array(proto_template_protocol, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_template_protocol (void)
{
	static dissector_handle_t proto_handle;

	proto_handle = create_dissector_handle(dissect, proto_template_protocol);
	dissector_add_uint( /*higher lvl protocol field */, /* value */, proto_handle);
}
