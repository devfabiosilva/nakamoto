#ifndef TESTUTIL_H
 #define TESTUTIL_H

#include <test/asserts.h>
#include <logger.h>
#include <nakamoto.h>
#include <string.h>
#include <rnd.h>
#include <stdlib.h>

#define VERSION_MAJOR_STR "0"
#define VERSION_MINOR_STR "1"
#define VERSION_REVISION_STR "2"

#define STR_CONST(str) str, (sizeof(str)-1)
#define VEC_CONST(vec) vec, sizeof(vec)
#define CLEAR_VECTOR(vec) memset(vec, 0, sizeof(vec));
#define COMPARE_VECTORS(vec1, vec2) is_vec_content_eq(vec1, sizeof(vec1), vec2, sizeof(vec2))
#define STR_SIZE(str) (sizeof(str)-1)

struct test_encryption_aes_256_t {
  uint8_t iv[16];
  uint8_t priv_key[32];
  uint8_t *encrypted_data;
  size_t encrypted_data_size;
  const char *message;
  size_t message_size;
};

void TEST_check_digest();
void TEST_entropy();
void TEST_generate_random_pass();
struct test_encryption_aes_256_t *TEST_encryption_aes_256();
void TEST_decryption_aes_256(struct test_encryption_aes_256_t *ctx);
void TEST_password_strength();
void TEST_pbkdf2();

#endif

