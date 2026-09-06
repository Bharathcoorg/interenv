use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// OWASP recommended memory cost for Argon2id (19 MiB).
pub const OWASP_ARGON2_MEM_KIB: u32 = 19 * 1024;
/// OWASP recommended iteration count for Argon2id.
pub const OWASP_ARGON2_ITERATIONS: u32 = 2;
/// OWASP recommended degree of parallelism for Argon2id.
pub const OWASP_ARGON2_PARALLELISM: u32 = 1;
/// Default derived master key output length in bytes.
pub const ARGON2_OUTPUT_LEN: usize = 32;

/// Generate 32 bytes of cryptographically secure random bytes for a master key.
pub fn generate_random_key() -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}

/// Generate a 16-byte random salt for key derivation.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Check if the system has sufficient memory (> 64 MiB) to run Argon2id safely.
pub fn check_available_memory() -> Result<(), String> {
    let avail_mb = get_available_memory_mb();
    if avail_mb < 64 {
        return Err(format!(
            "Insufficient system memory for Argon2id derivation: only {avail_mb} MiB available (< 64 MiB required)"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn get_available_memory_mb() -> u64 {
    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    extern "system" {
        fn GlobalMemoryStatusEx(status: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        memory_load: 0,
        total_phys: 0,
        avail_phys: 0,
        total_page_file: 0,
        avail_page_file: 0,
        total_virtual: 0,
        avail_virtual: 0,
        avail_extended_virtual: 0,
    };

    // SAFETY: GlobalMemoryStatusEx receives a valid pointer to an initialized
    // MemoryStatusEx struct whose length field is correctly set.
    let res = unsafe { GlobalMemoryStatusEx(&mut status) };
    if res != 0 {
        status.avail_phys / (1024 * 1024)
    } else {
        1024
    }
}

#[cfg(target_os = "linux")]
fn get_available_memory_mb() -> u64 {
    // SAFETY: libc::sysconf is called with valid system configuration query constants.
    unsafe {
        let pages = libc::sysconf(libc::_SC_AVPHYS_PAGES);
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if pages > 0 && page_size > 0 {
            ((pages as u64) * (page_size as u64)) / (1024 * 1024)
        } else {
            1024
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn get_available_memory_mb() -> u64 {
    // SAFETY: libc::sysconf is called with valid POSIX system query constants.
    unsafe {
        let pages = libc::sysconf(libc::_SC_PHYS_PAGES);
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if pages > 0 && page_size > 0 {
            ((pages as u64) * (page_size as u64)) / (1024 * 1024)
        } else {
            1024
        }
    }
}

#[cfg(not(any(windows, unix)))]
fn get_available_memory_mb() -> u64 {
    1024
}

/// Derive a 32-byte master key from a user passphrase and salt using OWASP-compliant Argon2id.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    check_available_memory()?;

    let params = Params::new(
        OWASP_ARGON2_MEM_KIB,
        OWASP_ARGON2_ITERATIONS,
        OWASP_ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 derivation error: {}", e))?;

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key() {
        let k1 = generate_random_key();
        let k2 = generate_random_key();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_kdf_consistency() {
        let salt = generate_salt();
        let pass = "super-secret-passphrase";
        let k1 = derive_key_from_passphrase(pass, &salt).unwrap();
        let k2 = derive_key_from_passphrase(pass, &salt).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn test_owasp_params() {
        const _: () = {
            assert!(OWASP_ARGON2_MEM_KIB >= 19 * 1024);
            assert!(OWASP_ARGON2_ITERATIONS >= 2);
            assert!(OWASP_ARGON2_PARALLELISM == 1);
        };
    }
}
