package graph_security

import rego.v1

# ---------- shared helpers ----------

escalation_primitives := {"ec2:runinstances", "lambda:createfunction", "ecs:registertaskdefinition"}

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

managed := [rc | some rc in input.resource_changes; rc.mode == "managed"]

# Config addresses carry no [index], so build the base address from type and name.
base(rc) := sprintf("%s.%s", [rc.type, rc.name])

# Parsed policy JSON; undefined when unknown at plan time or invalid.
policy_doc(rc) := json.unmarshal(rc.change.after.policy) if is_string(rc.change.after.policy)

# Direct references of `attr` that point at <prefix>.<name> (two segments only).
refs(addr, attr, prefix) := {ref |
	some r in input.configuration.root_module.resources
	r.address == addr
	some ref in r.expressions[attr].references
	startswith(ref, prefix)
	count(split(ref, ".")) == 2
}

# Wildcard-aware action match: "*", "iam:*", "iam:Pass*"
action_grants(s, target) if {
	some a in as_array(s.Action)
	glob.match(lower(a), [], lower(target))
}

is_broad(s) if {
	some r in as_array(s.Resource)
	contains(r, "*")
}

passrole_scoped(s) if {
	some _, cond in s.Condition
	cond["iam:PassedToService"]
}

# ---------- role -> Allow statements (the graph edge) ----------

role_grants contains {"role": role, "source": base(rc), "stmt": s} if {
	some rc in managed
	rc.type == "aws_iam_role_policy"
	some role in refs(base(rc), "role", "aws_iam_role.")
	doc := policy_doc(rc)
	some s in as_array(doc.Statement)
	s.Effect == "Allow"
}

role_grants contains {"role": role, "source": base(pol), "stmt": s} if {
	some att in managed
	att.type == "aws_iam_role_policy_attachment"
	some role in refs(base(att), "role", "aws_iam_role.")
	some pol_addr in refs(base(att), "policy_arn", "aws_iam_policy.")
	some pol in managed
	pol.type == "aws_iam_policy"
	base(pol) == pol_addr
	doc := policy_doc(pol)
	some s in as_array(doc.Statement)
	s.Effect == "Allow"
}

roles := {g.role | some g in role_grants}

passrole_broad(role) if {
	some g in role_grants
	g.role == role
	action_grants(g.stmt, "iam:PassRole")
	is_broad(g.stmt)
	not passrole_scoped(g.stmt)
}

primitives_for(role) := {p |
	some g in role_grants
	g.role == role
	some p in escalation_primitives
	action_grants(g.stmt, p)
}

# ---------- G1 ----------

deny contains msg if {
	some role in roles
	passrole_broad(role)
	prims := primitives_for(role)
	count(prims) > 0
	msg := sprintf("G1: %s can iam:PassRole on a wildcard target and create compute (%s)", [role, concat(", ", sort(prims))])
}

warn contains msg if {
	some g in role_grants
	g.stmt.NotAction
	msg := sprintf("G1: %s uses Allow+NotAction on %s; manual review required", [g.source, g.role])
}

warn contains msg if {
	some rc in managed
	rc.type in {"aws_iam_role_policy", "aws_iam_policy"}
	rc.change.after_unknown.policy == true
	msg := sprintf("G1: policy of %s is unknown at plan time (aws_iam_policy_document?); manual review required", [rc.address])
}

# ---------- G3: over-broad egress ----------

open_cidrs := {"0.0.0.0/0", "::/0"}

all_protocol(p) if p in {"-1", "all"}

all_protocol(-1)

full_port_range(from, to) if {
	is_number(from)
	is_number(to)
	from <= 0
	to >= 65535
}

unrestricted(proto, _, _) if all_protocol(proto)

unrestricted(_, from, to) if full_port_range(from, to)

# Works for the inline egress block and for aws_security_group_rule (same field names).
v4v6_open(e) if {
	some c in e.cidr_blocks
	c in open_cidrs
}

v4v6_open(e) if {
	some c in e.ipv6_cidr_blocks
	c in open_cidrs
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_security_group"
	some e in rc.change.after.egress
	v4v6_open(e)
	unrestricted(e.protocol, e.from_port, e.to_port)
	msg := sprintf("G3: %s allows unrestricted egress to the internet (protocol=%v)", [rc.address, e.protocol])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_security_group_rule"
	rc.change.after.type == "egress"
	v4v6_open(rc.change.after)
	unrestricted(rc.change.after.protocol, rc.change.after.from_port, rc.change.after.to_port)
	msg := sprintf("G3: %s allows unrestricted egress to the internet (protocol=%v)", [rc.address, rc.change.after.protocol])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_vpc_security_group_egress_rule"
	rc.change.after.cidr_ipv4 in open_cidrs
	unrestricted(rc.change.after.ip_protocol, rc.change.after.from_port, rc.change.after.to_port)
	msg := sprintf("G3: %s allows unrestricted IPv4 egress to the internet (ip_protocol=%v)", [rc.address, rc.change.after.ip_protocol])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_vpc_security_group_egress_rule"
	rc.change.after.cidr_ipv6 in open_cidrs
	unrestricted(rc.change.after.ip_protocol, rc.change.after.from_port, rc.change.after.to_port)
	msg := sprintf("G3: %s allows unrestricted IPv6 egress to the internet (ip_protocol=%v)", [rc.address, rc.change.after.ip_protocol])
}

# ---------- G2: unencrypted sink / missing audit trail ----------

# True when some companion resource of companion_type references <type>.<name> via attr.
linked(rc, companion_type, attr) if {
	some c in input.configuration.root_module.resources
	c.type == companion_type
	some ref in c.expressions[attr].references
	ref == base(rc)
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_s3_bucket"
	not linked(rc, "aws_s3_bucket_server_side_encryption_configuration", "bucket")
	msg := sprintf("G2: %s has no server-side encryption configuration", [rc.address])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_db_instance"
	not rc.change.after.storage_encrypted == true
	msg := sprintf("G2: %s is not encrypted at rest (storage_encrypted)", [rc.address])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_ebs_volume"
	not rc.change.after.encrypted == true
	msg := sprintf("G2: %s is not encrypted (encrypted)", [rc.address])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_secretsmanager_secret"
	not is_string(rc.change.after.kms_key_id)
	msg := sprintf("G2: %s has no customer-managed kms_key_id", [rc.address])
}

deny contains msg if {
	some rc in managed
	rc.type == "aws_dynamodb_table"
	not dynamodb_sse_enabled(rc)
	msg := sprintf("G2: %s has no server_side_encryption block enabled", [rc.address])
}

dynamodb_sse_enabled(rc) if {
	some s in rc.change.after.server_side_encryption
	s.enabled == true
}

warn contains msg if {
	some rc in managed
	rc.type == "aws_s3_bucket"
	not linked(rc, "aws_s3_bucket_logging", "bucket")
	not log_target(rc)
	msg := sprintf("G2: %s has no access logging companion (audit trail)", [rc.address])
}

warn contains msg if {
	some rc in managed
	rc.type == "aws_db_instance"
	count(log_exports(rc)) == 0
	msg := sprintf("G2: %s exports no logs to CloudWatch (audit trail)", [rc.address])
}

# Null-safe: the plan can carry the key with a null value, which object.get would return as-is.
log_exports(rc) := x if {
	x := rc.change.after.enabled_cloudwatch_logs_exports
	is_array(x)
} else := []

# True when some aws_s3_bucket_logging resource uses this bucket as target_bucket.
log_target(rc) if {
	some c in input.configuration.root_module.resources
	c.type == "aws_s3_bucket_logging"
	some ref in c.expressions.target_bucket.references
	ref == base(rc)
}
