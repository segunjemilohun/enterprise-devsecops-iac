package graph_security_test

import data.graph_security
import rego.v1

plan_of(rcs) := {"resource_changes": rcs}

sg_rc(egress) := {
	"address": "aws_security_group.s", "mode": "managed",
	"type": "aws_security_group", "name": "s",
	"change": {"after": {"egress": egress}, "after_unknown": {}},
}

sgr_rc(after) := {
	"address": "aws_security_group_rule.r", "mode": "managed",
	"type": "aws_security_group_rule", "name": "r",
	"change": {"after": after, "after_unknown": {}},
}

vpc_rc(after) := {
	"address": "aws_vpc_security_group_egress_rule.v", "mode": "managed",
	"type": "aws_vpc_security_group_egress_rule", "name": "v",
	"change": {"after": after, "after_unknown": {}},
}

blk(proto, from, to, v4, v6) := {
	"protocol": proto, "from_port": from, "to_port": to,
	"cidr_blocks": v4, "ipv6_cidr_blocks": v6,
}

# ---------- positives ----------
test_g3_inline_all_protocol_flagged if {
	p := plan_of([sg_rc([blk("-1", 0, 0, ["0.0.0.0/0"], [])])])
	count(graph_security.deny) == 1 with input as p
}

test_g3_inline_ipv6_flagged if {
	p := plan_of([sg_rc([blk("-1", 0, 0, [], ["::/0"])])])
	count(graph_security.deny) == 1 with input as p
}

test_g3_inline_full_tcp_range_flagged if {
	p := plan_of([sg_rc([blk("tcp", 0, 65535, ["0.0.0.0/0"], [])])])
	count(graph_security.deny) == 1 with input as p
}

test_g3_sg_rule_egress_flagged if {
	p := plan_of([sgr_rc({"type": "egress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []})])
	count(graph_security.deny) == 1 with input as p
}

test_g3_vpc_egress_rule_v4_flagged if {
	p := plan_of([vpc_rc({"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": null, "ip_protocol": "-1", "from_port": null, "to_port": null})])
	count(graph_security.deny) == 1 with input as p
}

test_g3_vpc_egress_rule_v6_flagged if {
	p := plan_of([vpc_rc({"cidr_ipv4": null, "cidr_ipv6": "::/0", "ip_protocol": "-1", "from_port": null, "to_port": null})])
	count(graph_security.deny) == 1 with input as p
}

# ---------- safe configs ----------
test_g3_https_only_allowed if {
	p := plan_of([sg_rc([blk("tcp", 443, 443, ["0.0.0.0/0"], [])])])
	count(graph_security.deny) == 0 with input as p
}

test_g3_all_protocol_to_private_cidr_safe if {
	p := plan_of([sg_rc([blk("-1", 0, 0, ["10.0.0.0/8"], [])])])
	count(graph_security.deny) == 0 with input as p
}

test_g3_vpc_rule_https_safe if {
	p := plan_of([vpc_rc({"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": null, "ip_protocol": "tcp", "from_port": 443, "to_port": 443})])
	count(graph_security.deny) == 0 with input as p
}

# ---------- edge cases ----------
test_g3_ingress_rule_ignored if {
	p := plan_of([sgr_rc({"type": "ingress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []})])
	count(graph_security.deny) == 0 with input as p
}

test_g3_empty_egress_safe if {
	p := plan_of([sg_rc([])])
	count(graph_security.deny) == 0 with input as p
}

test_g3_protocol_word_all_flagged if {
	p := plan_of([sg_rc([blk("all", 0, 0, ["0.0.0.0/0"], [])])])
	count(graph_security.deny) == 1 with input as p
}

test_g3_null_ports_with_tcp_not_flagged if {
	p := plan_of([sg_rc([blk("tcp", null, null, ["0.0.0.0/0"], [])])])
	count(graph_security.deny) == 0 with input as p
}

test_g3_dual_stack_single_block_collapses_to_one_message if {
	p := plan_of([sg_rc([blk("-1", 0, 0, ["0.0.0.0/0"], ["::/0"])])])
	count(graph_security.deny) == 1 with input as p
}
