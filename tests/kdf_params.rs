use interenv::crypto::kdf::{
    OWASP_ARGON2_ITERATIONS, OWASP_ARGON2_MEM_KIB, OWASP_ARGON2_PARALLELISM,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_argon2_owasp_compliance() {
    // OWASP recommendation for Argon2id is at least 19 MiB (19456 KiB) and at least 2 iterations
    assert!(
        OWASP_ARGON2_MEM_KIB >= 19 * 1024,
        "Argon2 memory must be at least 19 MiB (got {} KiB)",
        OWASP_ARGON2_MEM_KIB
    );
    assert!(
        OWASP_ARGON2_ITERATIONS >= 2,
        "Argon2 iterations must be at least 2 (got {})",
        OWASP_ARGON2_ITERATIONS
    );
    assert_eq!(
        OWASP_ARGON2_PARALLELISM, 1,
        "Argon2 parallelism must be 1 for single-lane predictability"
    );
}
