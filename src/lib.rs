extern crate wapc_guest as guest;
use guest::prelude::*;

use anyhow::anyhow;
use std::rc::Rc;

mod settings;
use settings::Settings;

use kubewarden_policy_sdk::{accept_request, reject_request, request::ValidationRequest};

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;

    let query = "spec.containers[*].securityContext.allowPrivilegeEscalation";
    if has_container_with_allow_privilege_escalation(query, &validation_req)? {
        return reject_request(
            Some(format!(
                "User '{}' cannot create containers with allowPrivilegeEscalation enabled",
                validation_req.request.user_info.username,
            )),
            None,
        );
    }

    let query = "spec.initContainers[*].securityContext.allowPrivilegeEscalation";
    if has_container_with_allow_privilege_escalation(query, &validation_req)? {
        return reject_request(
            Some(format!(
                "User '{}' cannot create initContainers with allowPrivilegeEscalation enabled",
                validation_req.request.user_info.username,
            )),
            None,
        );
    }

    accept_request()
}

fn has_container_with_allow_privilege_escalation(
    query: &str,
    validation_req: &ValidationRequest<Settings>,
) -> anyhow::Result<bool> {
    let containers_query = jmespatch::compile(query)
        .map_err(|e| anyhow!("Cannot parse jmespath expression: {:?}", e,))?;

    let raw_search_result = validation_req
        .search(containers_query)
        .map_err(|e| anyhow!("Error while searching request: {:?}", e,))?;
    if raw_search_result.is_null() {
        return Ok(false);
    }

    let search_result = raw_search_result.as_array().ok_or_else(|| {
        anyhow!(
            "Expected search matches to be an Array, got {:?} instead",
            raw_search_result
        )
    })?;

    Ok(search_result.contains(&Rc::new(jmespatch::Variable::Bool(true))))
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
