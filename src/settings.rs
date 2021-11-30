use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Settings {
    pub default_allow_privilege_escalation: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            default_allow_privilege_escalation: true,
        }
    }
}

impl kubewarden_policy_sdk::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}
