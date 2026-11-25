# Local tflint config. The bundled terraform ruleset needs no network access.
# The AWS ruleset is added in the CI step, pinned to an exact release.
config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
