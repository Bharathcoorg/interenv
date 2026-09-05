pub mod lockfile;
pub mod parser;

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, Zeroizing};

pub use lockfile::{InterLock, KeyProviderType, DEFAULT_LOCK_FILE};
pub use parser::{format_dotenv, is_valid_env_key, parse_dotenv, EnvMap};

#[derive(Debug, Clone, Default)]
pub struct Secrets(pub BTreeMap<String, Zeroizing<String>>);

impl Secrets {
    pub fn new(map: BTreeMap<String, Zeroizing<String>>) -> Self {
        Self(map)
    }

    pub fn from_env_map(env_map: &EnvMap) -> Self {
        let mut inner = BTreeMap::new();
        for (k, v) in env_map {
            inner.insert(k.clone(), Zeroizing::new(v.clone()));
        }
        Self(inner)
    }

    pub fn to_env_map(&self) -> EnvMap {
        let mut map = EnvMap::new();
        for (k, v) in self.0.iter() {
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
            let k_slice = unsafe { std::slice::from_raw_parts_mut(k.as_ptr() as *mut u8, k.len()) };
            k_slice.zeroize();
            v.zeroize();
        }
        self.0.clear();
    }
}
