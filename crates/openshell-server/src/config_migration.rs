// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lossless migration of legacy Snap authentication overrides.

use toml_edit::{DocumentMut, Item, Value};

pub(crate) fn migrate_mtls(input: &str) -> Result<String, toml_edit::TomlError> {
    let mut document = input.parse::<DocumentMut>()?;
    let mut changed = false;
    if let Some(gateway) = document
        .get_mut("openshell")
        .and_then(|root| existing_item(root, "gateway"))
    {
        changed |= disable_override(existing_item(gateway, "disable_tls"));
        changed |= disable_override(
            existing_item(gateway, "auth")
                .and_then(|auth| existing_item(auth, "allow_unauthenticated_users")),
        );
    }
    Ok(if changed {
        document.to_string()
    } else {
        input.to_owned()
    })
}

// Item::get_mut may insert an empty item when traversing dotted keys.
fn existing_item<'a>(item: &'a mut Item, key: &str) -> Option<&'a mut Item> {
    item.as_table_like_mut()?.get_mut(key)
}

fn disable_override(item: Option<&mut Item>) -> bool {
    let Some(value) = item.and_then(Item::as_value_mut) else {
        return false;
    };
    if value.as_bool() != Some(true) {
        return false;
    }
    let decor = value.decor().clone();
    *value = Value::from(false);
    *value.decor_mut() = decor;
    true
}

#[cfg(test)]
mod tests {
    use super::migrate_mtls;

    #[test]
    fn preserves_custom_settings_and_comments() {
        let input = r#"# operator configuration
[openshell]
version = 2
[openshell.gateway]
compute_driver = "docker"
allow_driver_config = true
disable_tls = true # local override
[openshell.gateway.auth]
allow_unauthenticated_users = true # legacy default
[openshell.drivers.docker]
network = "custom"
disable_tls = true # unrelated driver setting
"#;
        let expected = input
            .replace("disable_tls = true # local", "disable_tls = false # local")
            .replace(
                "allow_unauthenticated_users = true",
                "allow_unauthenticated_users = false",
            );
        let migrated = migrate_mtls(input).unwrap();
        assert_eq!(migrated, expected);
        assert_eq!(migrate_mtls(&migrated).unwrap(), migrated);
    }

    #[test]
    fn understands_quoted_dotted_and_inline_keys() {
        for input in [
            "openshell.gateway.disable_tls = true\n",
            "[\"openshell\".\"gateway\".\"auth\"]\n\"allow_unauthenticated_users\" = true\n",
            "openshell = { gateway = { disable_tls = true, auth = { allow_unauthenticated_users = true } } }\n",
        ] {
            assert_eq!(migrate_mtls(input).unwrap(), input.replace("true", "false"));
        }
    }

    #[test]
    fn secure_and_unrelated_values_unchanged() {
        for input in [
            "[openshell.gateway]\n",
            "[openshell.gateway]\ndisable_tls = false # secure\n",
            "[openshell.drivers.docker]\ndisable_tls = true\nallow_unauthenticated_users = true\n",
            "[openshell.gateway]\n# disable_tls = true\n",
            "[openshell.drivers.docker]\nscript = '''\ndisable_tls = true\n'''\n",
        ] {
            assert_eq!(migrate_mtls(input).unwrap(), input);
        }
    }

    #[test]
    fn rejects_invalid_toml() {
        for input in [
            "[openshell.gateway",
            "[openshell.gateway]\ndisable_tls = true\ndisable_tls = false\n",
        ] {
            assert!(migrate_mtls(input).is_err());
        }
    }
}
