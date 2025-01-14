//use anyhow::{anyhow, Result};
use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

mod settings;
use settings::Settings;

use kubewarden_policy_sdk::{
    accept_request, mutate_pod_spec_from_request, protocol_version_guest, reject_request,
    request::ValidationRequest, validate_settings,
};

use k8s_openapi::api::core::v1 as apicore;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request = ValidationRequest::<Settings>::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if pod_spec.is_none() {
                return accept_request();
            }
            let pod_spec = pod_spec.unwrap();
            let mut errors = vec![];

            let mutated_init_containers: Option<Vec<apicore::Container>> = match pod_spec
                .init_containers
                .clone()
            {
                Some(init_containers) => {
                    if has_allowed_privilege_escalation_container(init_containers.clone()) {
                        errors.push("one of the init containers has privilege escalation enabled");
                        None
                    } else {
                        patch_containers(
                            init_containers,
                            validation_request
                                .settings
                                .default_allow_privilege_escalation,
                        )
                    }
                }
                None => None,
            };
            let mutated_containers: Option<Vec<apicore::Container>> =
                if has_allowed_privilege_escalation_container(pod_spec.containers.clone()) {
                    errors.push("one of the containers has privilege escalation enabled");
                    None
                } else {
                    patch_containers(
                        pod_spec.containers.clone(),
                        validation_request
                            .settings
                            .default_allow_privilege_escalation,
                    )
                };

            if !errors.is_empty() {
                return reject_request(Some(errors.join(", ")), None, None, None);
            }

            if mutated_containers.is_some() || mutated_init_containers.is_some() {
                let init_containers =
                    mutated_init_containers.or_else(|| pod_spec.init_containers.clone());
                let containers = mutated_containers.unwrap_or_else(|| pod_spec.containers.clone());

                mutate_pod_spec_from_request(
                    validation_request,
                    apicore::PodSpec {
                        init_containers,
                        containers,
                        ..pod_spec
                    },
                )
            } else {
                accept_request()
            }
        }
        Err(_) => reject_request(
            Some("Cannot parse validation request".to_string()),
            None,
            None,
            None,
        ),
    }
}

fn has_allowed_privilege_escalation_container(containers: Vec<apicore::Container>) -> bool {
    containers.into_iter().any(|container| {
        container.security_context.is_some_and(|security_context| {
            security_context.allow_privilege_escalation.unwrap_or(false)
        })
    })
}

fn patch_containers(
    containers: Vec<apicore::Container>,
    default_allow_privilege_escalation: bool,
) -> Option<Vec<apicore::Container>> {
    if default_allow_privilege_escalation {
        // the default behavior or Kubernetes is to allow privilege escalation
        return None;
    }

    let mut mutations_done = false;
    let new_containers: Vec<apicore::Container> = containers
        .iter()
        .map(|c| {
            let new_sc = match c.security_context.clone() {
                Some(sc) => {
                    if sc.allow_privilege_escalation == Some(false) {
                        sc
                    } else {
                        mutations_done = true;
                        apicore::SecurityContext {
                            allow_privilege_escalation: Some(false),
                            ..sc
                        }
                    }
                }
                None => {
                    mutations_done = true;
                    apicore::SecurityContext {
                        allow_privilege_escalation: Some(false),
                        ..Default::default()
                    }
                }
            };

            apicore::Container {
                security_context: Some(new_sc),
                ..c.clone()
            }
        })
        .collect();

    if mutations_done {
        Some(new_containers)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn reject_container_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file = "test_data/req_pod_with_container_with_security_context_and_allowPrivilegeEscalation.json";
        let tc = Testcase {
            name: String::from("Reject"),
            fixture_file: String::from(request_file),
            settings: Settings::default(),
            expected_validation_result: false,
        };

        let _ = tc.eval(validate)?;
        Ok(())
    }

    #[test]
    fn reject_pod_with_init_container_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file =
            "test_data/req_pod_with_init_container_with_security_context_and_allowPrivilegeEscalation.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings::default(),
            expected_validation_result: false,
        };

        let _ = tc.eval(validate)?;
        Ok(())
    }

    #[test]
    fn accept_pod_with_allow_privilege_escalation_disabled() -> Result<()> {
        let request_file = "test_data/req_pod_with_allowPrivilegeEscalation_disabled.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings {
                default_allow_privilege_escalation: false,
            },
            expected_validation_result: true,
        };

        let vr = tc.eval(validate)?;

        // no need to mutate the object
        assert!(vr.mutated_object.is_none());
        Ok(())
    }

    #[test]
    fn accept_pod_without_security_context() -> Result<()> {
        let request_file = "test_data/req_pod_without_security_context.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings::default(),
            expected_validation_result: true,
        };

        let _ = tc.eval(validate)?;
        Ok(())
    }

    #[test]
    fn mutate_pod_without_security_context() -> Result<()> {
        let request_file = "test_data/req_pod_without_security_context.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings {
                default_allow_privilege_escalation: false,
            },
            expected_validation_result: true,
        };

        let vr = tc.eval(validate)?;
        assert!(vr.mutated_object.is_some());

        Ok(())
    }

    #[test]
    fn reject_deployment_with_container_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file = "test_data/deployment_with_allow_privileged_escalation.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings::default(),
            expected_validation_result: false,
        };

        let _ = tc.eval(validate)?;
        Ok(())
    }
}
