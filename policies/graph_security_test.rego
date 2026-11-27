package graph_security_test

import data.graph_security
import rego.v1

# ---------- builders ----------
role_rc(name) := {
	"address": sprintf("aws_iam_role.%s", [name]), "mode": "managed",
	"type": "aws_iam_role", "name": name,
	"change": {"after": {"name": name}, "after_unknown": {}},
}

pol_rc(type, name, stmts) := {
	"address": sprintf("%s.%s", [type, name]), "mode": "managed",
	"type": type, "name": name,
	"change": {
		"after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": stmts})},
		"after_unknown": {},
	},
}

inline_cfg(name, role) := {
	"address": sprintf("aws_iam_role_policy.%s", [name]),
	"expressions": {"role": {"references": [
		sprintf("aws_iam_role.%s.id", [role]),
		sprintf("aws_iam_role.%s", [role]),
	]}},
}

plan(rcs, cfgs) := {
	"resource_changes": rcs,
	"configuration": {"root_module": {"resources": cfgs}},
}

allow(action, resource) := {"Effect": "Allow", "Action": action, "Resource": resource}

# ---------- positives ----------
test_g1_single_policy_pair_flagged if {
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [allow(["iam:PassRole", "lambda:CreateFunction"], "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 1 with input as p
}

test_g1_cross_policy_same_role_flagged if {
	p := plan(
		[
			role_rc("r"),
			pol_rc("aws_iam_role_policy", "a", [allow("iam:PassRole", "*")]),
			pol_rc("aws_iam_role_policy", "b", [allow("ec2:RunInstances", "*")]),
		],
		[inline_cfg("a", "r"), inline_cfg("b", "r")],
	)
	count(graph_security.deny) == 1 with input as p
}

test_g1_attachment_path_flagged if {
	p := plan(
		[
			role_rc("r"),
			pol_rc("aws_iam_policy", "managed", [allow(["iam:PassRole", "ecs:RegisterTaskDefinition"], ["*"])]),
			{
				"address": "aws_iam_role_policy_attachment.att", "mode": "managed",
				"type": "aws_iam_role_policy_attachment", "name": "att",
				"change": {"after": {}, "after_unknown": {}},
			},
		],
		[{
			"address": "aws_iam_role_policy_attachment.att",
			"expressions": {
				"role": {"references": ["aws_iam_role.r.name", "aws_iam_role.r"]},
				"policy_arn": {"references": ["aws_iam_policy.managed.arn", "aws_iam_policy.managed"]},
			},
		}],
	)
	count(graph_security.deny) == 1 with input as p
}

test_g1_wildcard_actions_flagged if {
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [allow(["iam:*", "lambda:*"], "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 1 with input as p
}

test_g1_full_admin_star_flagged if {
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [allow("*", "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 1 with input as p
}

# ---------- safe configs ----------
test_g1_passrole_only_safe if {
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [allow("iam:PassRole", "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 0 with input as p
}

test_g1_split_across_different_roles_safe if {
	p := plan(
		[
			role_rc("a"), role_rc("b"),
			pol_rc("aws_iam_role_policy", "pa", [allow("iam:PassRole", "*")]),
			pol_rc("aws_iam_role_policy", "pb", [allow("lambda:CreateFunction", "*")]),
		],
		[inline_cfg("pa", "a"), inline_cfg("pb", "b")],
	)
	count(graph_security.deny) == 0 with input as p
}

test_g1_scoped_passrole_arn_safe if {
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [
			allow("iam:PassRole", "arn:aws:iam::123456789012:role/app"),
			allow("lambda:CreateFunction", "*"),
		])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 0 with input as p
}

# ---------- edge cases ----------
test_g1_deny_effect_ignored if {
	deny_stmt := {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [deny_stmt, allow("lambda:CreateFunction", "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 0 with input as p
}

test_g1_passed_to_service_condition_downgrades if {
	scoped := {
		"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
		"Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
	}
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [scoped, allow("lambda:CreateFunction", "*")])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.deny) == 0 with input as p
}

test_g1_notaction_warns if {
	na := {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}
	p := plan(
		[role_rc("r"), pol_rc("aws_iam_role_policy", "p", [na])],
		[inline_cfg("p", "r")],
	)
	count(graph_security.warn) == 1 with input as p
}

test_g1_unknown_policy_warns_not_silent if {
	p := plan(
		[{
			"address": "aws_iam_role_policy.p", "mode": "managed",
			"type": "aws_iam_role_policy", "name": "p",
			"change": {"after": {}, "after_unknown": {"policy": true}},
		}],
		[],
	)
	count(graph_security.warn) == 1 with input as p
	count(graph_security.deny) == 0 with input as p
}
