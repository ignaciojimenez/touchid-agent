#ifndef SECUREENCLAVE_BRIDGE_H
#define SECUREENCLAVE_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

// All functions return 0 on success, non-zero on error.
// On error, *error_out is set to a malloc'd UTF-8 string the caller must free.
// All output buffers are malloc'd; the caller must free them.

// Generate a new Secure Enclave-backed P-256 signing key.
// require_touch: 1 = .biometryAny enforced per signing op, 0 = .privateKeyUsage only.
// key_data_out: opaque SEP-wrapped blob (dataRepresentation).
// pubkey_out:   uncompressed EC point, 65 bytes (0x04 || X || Y).
int se_generate(
    int require_touch,
    uint8_t **key_data_out, size_t *key_data_len,
    uint8_t **pubkey_out,   size_t *pubkey_len,
    char **error_out
);

// Recover the uncompressed EC public point (65 bytes) from a key blob.
int se_public_key(
    const uint8_t *key_data, size_t key_data_len,
    uint8_t **pubkey_out,    size_t *pubkey_len,
    char **error_out
);

// Sign a 32-byte SHA-256 digest with a previously-generated SE key blob.
// digest_len must equal 32. The digest is treated as pre-hashed input;
// CryptoKit will not re-hash it. Output is a DER-encoded ECDSA signature.
int se_sign(
    const uint8_t *key_data, size_t key_data_len,
    const uint8_t *digest,   size_t digest_len,
    uint8_t **sig_out,       size_t *sig_len,
    char **error_out
);

#endif
