#!/usr/bin/env bats

set -e

@test "reject pod with allowPrivilegeEscalation disabled" {
  output="$(kwctl run annotated-policy.wasm test_data/req_pod_with_allowPrivilegeEscalation_disabled.json)"
  [ "$(echo "$output" | jq '.allowed')" = "false" ]
  [ "$(echo "$output" | jq '.status.message')" = 'one of the containers has privilege escalation enabled' ]
}

@test "accept pod without security context" {
  output="$(kwctl run annotated-policy.wasm test_data/req_pod_without_security_context.json)"
  [ "$(echo "$output" | jq '.allowed')" = "true" ]
}

@test "reject pod with container with security context and allowPrivilegeEscalation set to true" {
  output="$(kwctl run annotated-policy.wasm test_data/req_pod_with_container_with_security_context_and_allowPrivilegeEscalation.json)"
  [ "$(echo "$output" | jq '.allowed')" = "false" ]
  [ "$(echo "$output" | jq '.status.message')" = 'one of the containers has privilege escalation enabled' ]
}

@test "reject pod with init container with security context and allowPrivilegeEscalation set to true" {
  output="$(kwctl run annotated-policy.wasm test_data/req_pod_with_init_container_with_security_context_and_allowPrivilegeEscalation.json)"
  [ "$(echo "$output" | jq '.allowed')" = "false" ]
  [ "$(echo "$output" | jq '.status.message')" = 'one of the init containers has privilege escalation enabled' ]
}
