use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_with_no_settings() -> Result<(), ()> {
        let payload = "settings:";
        let settings = serde_yaml::from_str::<Settings>(payload);
        assert!(
            settings.is_ok(),
            "settings parse should not fails if it is empty"
        );
        assert!(
            settings.unwrap().default_allow_privilege_escalation,
            "default_allow_privilege_escalation should be 'true' when not defined by the user"
        );
        Ok(())
    }

    #[test]
    fn test_policy_with_settings() -> Result<(), serde_yaml::Error> {
        let payload = "default_allow_privilege_escalation: true";
        let settings = serde_yaml::from_str::<Settings>(payload)?;
        assert!(settings.default_allow_privilege_escalation);

        let payload = "default_allow_privilege_escalation: false";
        let settings = serde_yaml::from_str::<Settings>(payload)?;
        assert!(!settings.default_allow_privilege_escalation);
        Ok(())
    }
}
