#ifndef SECUREENCLAVE_H
#define SECUREENCLAVE_H

#include <stdint.h>
#include <stddef.h>

// Generate a new ECDSA P-256 key.
// label: human-readable name for the key
// tag: unique application tag for Keychain lookup
// require_touch: 1 if Touch ID is required per signing operation, 0 otherwise
// use_se: 1 to store in the Secure Enclave, 0 for software-backed Keychain key
// Returns 0 on success, -1 on error.
int se_generate_key(const char *label, const char *tag, int require_touch,
                    int use_se, char **error_out);

// Sign a SHA-256 digest using the key identified by tag.
// digest must be exactly 32 bytes.
// On success, sig_out and sig_len are set to the DER-encoded ECDSA signature (caller must free sig_out).
// Returns 0 on success, -1 on error.
int se_sign(const char *tag, const uint8_t *digest, size_t digest_len,
            uint8_t **sig_out, size_t *sig_len, char **error_out);

// Get the uncompressed EC public key (65 bytes: 0x04 || x || y) for the key identified by tag.
// On success, pub_out and pub_len are set (caller must free pub_out).
// Returns 0 on success, -1 on error.
int se_get_public_key(const char *tag, uint8_t **pub_out, size_t *pub_len, char **error_out);

// List all keys matching tag_prefix.
// Returns a newline-delimited string of "tag\tlabel" pairs in result_out (caller must free).
// Returns 0 on success, -1 on error.
int se_list_keys(const char *tag_prefix, char **result_out, char **error_out);

// Delete the key identified by tag.
// Returns 0 on success, -1 on error.
int se_delete_key(const char *tag, char **error_out);

// Delete all keys matching tag_prefix.
// Returns 0 on success, -1 on error.
int se_delete_all_keys(const char *tag_prefix, char **error_out);

#endif
