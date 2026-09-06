use interenv::crypto::kdf::{
    OWASP_ARGON2_ITERATIONS, OWASP_ARGON2_MEM_KIB, OWASP_ARGON2_PARALLELISM,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_argon2_owasp_compliance() {
    // RFC 9106 second recommended parameter set for Argon2id:
    // t=3, p=4, m=2^16 KiB (64 MiB).
    assert!(
        OWASP_ARGON2_MEM_KIB >= 64 * 1024,
        "Argon2 memory must be at least 64 MiB (got {} KiB)",
        OWASP_ARGON2_MEM_KIB
    );
    assert!(
        OWASP_ARGON2_ITERATIONS >= 3,
        "Argon2 iterations must be at least 3 (got {})",
        OWASP_ARGON2_ITERATIONS
    );
    assert!(
        OWASP_ARGON2_PARALLELISM >= 4,
        "Argon2 parallelism must be at least 4 (got {})",
        OWASP_ARGON2_PARALLELISM
    );
}
