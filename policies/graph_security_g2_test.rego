package graph_security_test

import data.graph_security
import rego.v1

rc_of(type, name, after) := {
	"address": sprintf("%s.%s", [type, name]), "mode": "managed",
	"type": type, "name": name,
	"change": {"after": after, "after_unknown": {}},
}

companion_cfg(type, name, bucket) := {
	"address": sprintf("%s.%s", [type, name]),
	"type": type,
	"expressions": {"bucket": {"references": [
		sprintf("aws_s3_bucket.%s.id", [bucket]),
		sprintf("aws_s3_bucket.%s", [bucket]),
	]}},
}

g2_plan(rcs, cfgs) := {
	"resource_changes": rcs,
	"configuration": {"root_module": {"resources": cfgs}},
}

sse_cfg(bucket) := companion_cfg("aws_s3_bucket_server_side_encryption_configuration", bucket, bucket)

log_cfg(bucket) := companion_cfg("aws_s3_bucket_logging", bucket, bucket)

g2_denies(p) := {m | some m in graph_security.deny with input as p; startswith(m, "G2:")}

g2_warns(p) := {m | some m in graph_security.warn with input as p; startswith(m, "G2:")}

# ---------- positives ----------
test_g2_bucket_without_sse_flagged if {
	p := g2_plan([rc_of("aws_s3_bucket", "b", {})], [])
	count(g2_denies(p)) == 1
}

test_g2_bucket_sse_for_other_bucket_still_flagged if {
	p := g2_plan([rc_of("aws_s3_bucket", "a", {}), rc_of("aws_s3_bucket", "b", {})], [sse_cfg("b")])
	count(g2_denies(p)) == 1
}

test_g2_db_unencrypted_flagged if {
	p := g2_plan([rc_of("aws_db_instance", "d", {"storage_encrypted": false})], [])
	count(g2_denies(p)) == 1
}

test_g2_ebs_unencrypted_flagged if {
	p := g2_plan([rc_of("aws_ebs_volume", "v", {"encrypted": false})], [])
	count(g2_denies(p)) == 1
}

test_g2_secret_without_kms_flagged if {
	p := g2_plan([rc_of("aws_secretsmanager_secret", "s", {"kms_key_id": null})], [])
	count(g2_denies(p)) == 1
}

test_g2_dynamodb_without_sse_flagged if {
	p := g2_plan([rc_of("aws_dynamodb_table", "t", {"server_side_encryption": []})], [])
	count(g2_denies(p)) == 1
}

test_g2_bucket_without_logging_warns if {
	p := g2_plan([rc_of("aws_s3_bucket", "b", {})], [sse_cfg("b")])
	count(g2_warns(p)) == 1
	count(g2_denies(p)) == 0
}

test_g2_db_without_log_exports_warns if {
	p := g2_plan([rc_of("aws_db_instance", "d", {"storage_encrypted": true, "enabled_cloudwatch_logs_exports": []})], [])
	count(g2_warns(p)) == 1
	count(g2_denies(p)) == 0
}

# ---------- safe configs ----------
test_g2_bucket_with_sse_and_logging_clean if {
	p := g2_plan([rc_of("aws_s3_bucket", "b", {})], [sse_cfg("b"), log_cfg("b")])
	count(g2_denies(p)) == 0
	count(g2_warns(p)) == 0
}

test_g2_db_encrypted_with_logs_clean if {
	p := g2_plan([rc_of("aws_db_instance", "d", {"storage_encrypted": true, "enabled_cloudwatch_logs_exports": ["postgresql"]})], [])
	count(g2_denies(p)) == 0
	count(g2_warns(p)) == 0
}

test_g2_ebs_encrypted_clean if {
	p := g2_plan([rc_of("aws_ebs_volume", "v", {"encrypted": true})], [])
	count(g2_denies(p)) == 0
}

test_g2_secret_with_kms_clean if {
	p := g2_plan([rc_of("aws_secretsmanager_secret", "s", {"kms_key_id": "alias/app"})], [])
	count(g2_denies(p)) == 0
}

test_g2_dynamodb_sse_enabled_clean if {
	p := g2_plan([rc_of("aws_dynamodb_table", "t", {"server_side_encryption": [{"enabled": true}]})], [])
	count(g2_denies(p)) == 0
}

# ---------- edge cases ----------
test_g2_db_missing_encrypted_field_flagged if {
	p := g2_plan([rc_of("aws_db_instance", "d", {})], [])
	count(g2_denies(p)) == 1
}

test_g2_db_missing_log_exports_field_warns if {
	p := g2_plan([rc_of("aws_db_instance", "d", {"storage_encrypted": true})], [])
	count(g2_warns(p)) == 1
}

test_g2_unrelated_resource_ignored if {
	p := g2_plan([rc_of("aws_sqs_queue", "q", {})], [])
	count(g2_denies(p)) == 0
	count(g2_warns(p)) == 0
}

# ---------- D12 / D13 regressions ----------
test_g2_db_null_log_exports_warns if {
	p := g2_plan([rc_of("aws_db_instance", "d", {"storage_encrypted": true, "enabled_cloudwatch_logs_exports": null})], [])
	count(g2_warns(p)) == 1
}

test_g2_log_target_bucket_not_warned if {
	logging := {
		"address": "aws_s3_bucket_logging.data",
		"type": "aws_s3_bucket_logging",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]},
			"target_bucket": {"references": ["aws_s3_bucket.logs.id", "aws_s3_bucket.logs"]},
		},
	}
	p := g2_plan(
		[rc_of("aws_s3_bucket", "data", {}), rc_of("aws_s3_bucket", "logs", {})],
		[sse_cfg("data"), sse_cfg("logs"), logging],
	)
	count(g2_warns(p)) == 0
}

test_g2_unrelated_target_does_not_exempt if {
	logging := {
		"address": "aws_s3_bucket_logging.data",
		"type": "aws_s3_bucket_logging",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]},
			"target_bucket": {"references": ["aws_s3_bucket.logs.id", "aws_s3_bucket.logs"]},
		},
	}
	p := g2_plan(
		[rc_of("aws_s3_bucket", "other", {}), rc_of("aws_s3_bucket", "data", {}), rc_of("aws_s3_bucket", "logs", {})],
		[logging],
	)
	count(g2_warns(p)) == 1
}
