/// Lockfile schema and serialization.
pub mod lockfile;
/// Dotenv file syntax parser and formatter.
pub mod parser;

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, Zeroizing};

pub use lockfile::{InterLock, KeyProviderType, DEFAULT_LOCK_FILE};
pub use parser::{format_dotenv, is_valid_env_key, parse_dotenv, EnvMap};

/// Secure wrapper for environment secrets ensuring in-place heap memory zeroization on drop.
#[derive(Debug, Clone, Default)]
pub struct Secrets(BTreeMap<String, Zeroizing<String>>);

impl Secrets {
    /// Construct a Secrets container wrapping a map of zeroizing values.
    pub fn new(map: BTreeMap<String, Zeroizing<String>>) -> Self {
        Self(map)
    }

    /// Construct a Secrets container from an existing EnvMap.
    pub fn from_env_map(env_map: &EnvMap) -> Self {
        let mut inner = BTreeMap::new();
        for (k, v) in env_map {
            inner.insert(k.clone(), Zeroizing::new(v.clone()));
        }
        Self(inner)
    }

    /// Convert back to an EnvMap.
    pub fn to_env_map(&self) -> EnvMap {
        let mut map = EnvMap::new();
        for (k, v) in &self.0 {
            map.insert(k.clone(), (**v).clone());
        }
        map
    }
}

impl Deref for Secrets {
    type Target = BTreeMap<String, Zeroizing<String>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Secrets {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        for (k, v) in self.0.iter_mut() {
            // SAFETY: k.as_ptr() points to valid String buffer of length k.len() which
            // is safe to wipe immediately before dropping the BTreeMap allocation.
            let k_slice = unsafe { std::slice::from_raw_parts_mut(k.as_ptr() as *mut u8, k.len()) };
            k_slice.zeroize();
            v.zeroize();
        }
        self.0.clear();
    }
}

impl Zeroize for Secrets {
    fn zeroize(&mut self) {
        for (k, v) in self.0.iter_mut() {
            // SAFETY: k.as_ptr() points to valid String buffer of length k.len() which
            // is safe to wipe immediately before clearing map entries.
            let k_slice = unsafe { std::slice::from_raw_parts_mut(k.as_ptr() as *mut u8, k.len()) };
            k_slice.zeroize();
            v.zeroize();
        }
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_construction_and_deref() {
        let mut map = BTreeMap::new();
        map.insert(
            "API_KEY".to_string(),
            Zeroizing::new("secret123".to_string()),
        );
        let mut secrets = Secrets::new(map);
        assert_eq!(&**secrets.get("API_KEY").unwrap(), "secret123");

        secrets.insert("ANOTHER".to_string(), Zeroizing::new("val".to_string()));
        assert_eq!(&**secrets.get("ANOTHER").unwrap(), "val");
    }

    #[test]
    fn test_secrets_env_map_roundtrip() {
        let mut env_map = EnvMap::new();
        env_map.insert("DB_PASS".to_string(), "pass456".to_string());
        let secrets = Secrets::from_env_map(&env_map);
        let recovered = secrets.to_env_map();
        assert_eq!(recovered.get("DB_PASS").unwrap(), "pass456");
    }

    #[test]
    fn test_secrets_zeroize() {
        let mut map = BTreeMap::new();
        map.insert("TOKEN".to_string(), Zeroizing::new("token789".to_string()));
        let mut secrets = Secrets::new(map);
        assert_eq!(secrets.len(), 1);
        secrets.zeroize();
        assert!(secrets.is_empty());
    }
}
