#!/usr/bin/env bats

@test "accept pod with allowPrivilegeEscalation disabled" {
  run kwctl run \
    -r test_data/req_pod_with_allowPrivilegeEscalation_disabled.json \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept pod without security context" {
  run kwctl run policy.wasm -r test_data/req_pod_without_security_context.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject pod with container with security context and allowPrivilegeEscalation set to true" {
  run kwctl run \
    -r test_data/req_pod_with_container_with_security_context_and_allowPrivilegeEscalation.json \
    --settings-json '{"allowPrivilegeEscalation": false}' \
    policy.wasm 

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*one of the containers has privilege escalation enabled.*") -ne 0 ]
}

@test "reject pod with init container with security context and allowPrivilegeEscalation set to true" {
  run kwctl run \
    -r test_data/req_pod_with_init_container_with_security_context_and_allowPrivilegeEscalation.json \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*one of the init containers has privilege escalation enabled.*") -ne 0 ]
}
