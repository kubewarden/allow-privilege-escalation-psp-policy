extern crate wapc_guest as guest;
use guest::prelude::*;

mod settings;
use settings::Settings;

use kubewarden_policy_sdk::{accept_request, reject_request, request::ValidationRequest};

use k8s_openapi::api::core::v1 as apicore;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;
    let pod = serde_json::from_value::<apicore::Pod>(validation_req.request.object)?;

    let any_allowed_privilege_escalation_container = pod
        .spec
        .map(|spec| {
            has_allowed_privilege_escalation_container(spec.init_containers)
                || has_allowed_privilege_escalation_container(Some(spec.containers))
        })
        .unwrap_or(false);

    if any_allowed_privilege_escalation_container {
        reject_request(
            Some(format!(
                "User '{}' cannot create containers with allowPrivilegeEscalation enabled",
                validation_req.request.user_info.username,
            )),
            None,
        )
    } else {
        accept_request()
    }
}

fn has_allowed_privilege_escalation_container(containers: Option<Vec<apicore::Container>>) -> bool {
    containers.unwrap_or_default().into_iter().any(|container| {
        container
            .security_context
            .map_or(false, |security_context| {
                security_context.allow_privilege_escalation.unwrap_or(false)
            })
    })
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
            settings: Settings {},
            expected_validation_result: false,
        };

        let _ = tc.eval(validate);
        Ok(())
    }

    #[test]
    fn reject_pod_with_init_container_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file =
            "test_data/req_pod_with_init_container_with_security_context_and_allowPrivilegeEscalation.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings {},
            expected_validation_result: false,
        };

        let _ = tc.eval(validate);
        Ok(())
    }

    #[test]
    fn accept_pod_with_allow_privilege_escalation_disabled() -> Result<()> {
        let request_file = "test_data/req_pod_with_allowPrivilegeEscalation_disabled.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings {},
            expected_validation_result: true,
        };

        let _ = tc.eval(validate);
        Ok(())
    }

    #[test]
    fn accept_pod_without_security_context() -> Result<()> {
        let request_file = "test_data/req_pod_without_security_context.json";
        let tc = Testcase {
            name: String::from("Accept"),
            fixture_file: String::from(request_file),
            settings: Settings {},
            expected_validation_result: true,
        };

        let _ = tc.eval(validate);
        Ok(())
    }
}
