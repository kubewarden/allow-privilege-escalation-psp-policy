extern crate wapc_guest as guest;
use guest::prelude::*;

use anyhow::anyhow;
use std::rc::Rc;

mod settings;
use settings::Settings;

use chimera_kube_policy_sdk::{accept_request, reject_request, request::ValidationRequest};

use jmespatch;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_req = ValidationRequest::<Settings>::new(payload)?;

    if validation_req.is_request_made_by_trusted_user() {
        return accept_request();
    }

    if has_container_with_allow_privilege_escalation(&validation_req)? {
        return reject_request(Some(format!(
            "User '{}' cannot create containers with allowPrivilegeEscalation enabled",
            validation_req.request.user_info.username,
        )));
    }

    if pod_spec_allows_privilege_escalation(&validation_req)? {
        return reject_request(Some(format!(
            "User '{}' cannot create Pods with allowPrivilegeEscalation enabled",
            validation_req.request.user_info.username,
        )));
    }

    accept_request()
}

fn has_container_with_allow_privilege_escalation(
    validation_req: &ValidationRequest<Settings>,
) -> anyhow::Result<bool> {
    let query = "spec.containers[*].securityContext.allowPrivilegeEscalation";

    let containers_query = jmespatch::compile(query)
        .or_else(|e| Err(anyhow!("Cannot parse jmespath expression: {:?}", e,)))?;

    let raw_search_result = validation_req
        .search(containers_query)
        .or_else(|e| Err(anyhow!("Error while searching request: {:?}", e,)))?;
    let search_result = raw_search_result.as_array().ok_or_else(|| {
        anyhow!(
            "Expected search matches to be an Array, got {:?} instead",
            raw_search_result
        )
    })?;

    Ok(search_result.contains(&Rc::new(jmespatch::Variable::Bool(true))))
}

fn pod_spec_allows_privilege_escalation(
    validation_req: &ValidationRequest<Settings>,
) -> anyhow::Result<bool> {
    let query = "spec.securityContext.allowPrivilegeEscalation";

    let containers_query = jmespatch::compile(query)
        .or_else(|e| Err(anyhow!("Cannot parse jmespath expression: {:?}", e,)))?;

    let search_result = validation_req
        .search(containers_query)
        .or_else(|e| Err(anyhow!("Error while searching request: {:?}", e,)))?;

    Ok(search_result.is_truthy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serde_json::json;
    use std::fs::File;
    use std::io::BufReader;

    use chimera_kube_policy_sdk::response::ValidationResponse;

    macro_rules! configuration {
        (key: $key:tt, value: $value:tt, allowed_users: $users:expr, allowed_groups: $groups:expr) => {
            Settings {
                allowed_users: $users.split(",").map(String::from).collect(),
                allowed_groups: $groups.split(",").map(String::from).collect(),
            };
        };
    }

    fn read_request_file(path: &str) -> Result<serde_json::Value> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let v = serde_json::from_reader(reader)?;

        Ok(v)
    }

    fn make_validate_payload(request_file: &str, settings: &Settings) -> String {
        let req = read_request_file(request_file).unwrap();
        let payload = json!({
            "settings": settings,
            "request": req
        });

        payload.to_string()
    }

    struct Testcase {
        pub name: String,
        pub fixture_file: String,
        pub expected_validation_result: bool,
        pub settings: Settings,
    }

    impl Testcase {
        fn eval(&self) -> Result<()> {
            let payload = make_validate_payload(self.fixture_file.as_str(), &self.settings);
            let raw_result = validate(payload.as_bytes()).unwrap();
            let result: ValidationResponse = serde_json::from_slice(&raw_result)?;
            assert_eq!(
                result.accepted, self.expected_validation_result,
                "Failure for test case: '{}': got {:?} instead of {:?}",
                self.name, result.accepted, self.expected_validation_result,
            );

            Ok(())
        }
    }

    #[test]
    fn container_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file = "test_data/req_pod_with_container_with_security_context_and_allowPrivilegeEscalation.json";
        let tests = vec![
            Testcase {
                name: String::from("Accept request because user is trusted"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "admin,kubernetes-admin",
                allowed_groups: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Accept request because user belongs to a trusted group"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "",
                allowed_groups: "system:masters"),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Reject request because user is not trusted"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "alice",
                allowed_groups: "trusted_users"),
                expected_validation_result: false,
            },
        ];

        for tc in tests.iter() {
            let _ = tc.eval();
        }

        Ok(())
    }

    #[test]
    fn pod_with_allow_privilege_escalation_enabled() -> Result<()> {
        let request_file =
            "test_data/req_pod_with_security_context_and_allowPrivilegedEscalation_enabled.json";
        let tests = vec![
            Testcase {
                name: String::from("Accept request because user is trusted"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "admin,kubernetes-admin",
                allowed_groups: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Accept request because user belongs to a trusted group"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "",
                allowed_groups: "system:masters"),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Reject request because user is not trusted"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "alice",
                allowed_groups: "trusted_users"),
                expected_validation_result: false,
            },
        ];

        for tc in tests.iter() {
            let _ = tc.eval();
        }

        Ok(())
    }

    #[test]
    fn pod_without_security_context() -> Result<()> {
        let request_file = "test_data/req_pod_without_security_context.json";
        let tests = vec![
            Testcase {
                name: String::from("Accept request because user is trusted"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "admin,kubernetes-admin",
                allowed_groups: ""),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Accept request because user belongs to a trusted group"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "",
                allowed_groups: "system:masters"),
                expected_validation_result: true,
            },
            Testcase {
                name: String::from("Accept request even if user is not trusted because allowPrivilegeEscalation is not set"),
                fixture_file: String::from(request_file),
                settings: configuration!(
                key: "dedicated",
                value: "tenantA",
                allowed_users: "alice",
                allowed_groups: "trusted_users"),
                expected_validation_result: true,
            },
        ];

        for tc in tests.iter() {
            let _ = tc.eval();
        }

        Ok(())
    }
}
