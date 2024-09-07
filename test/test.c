#include <test/asserts.h>
#include <logger.h>
#include <nakamoto.h>
#include <string.h>
#include <rnd.h>
#include <stdlib.h>

#define VERSION_MAJOR_STR "0"
#define VERSION_MINOR_STR "1"
#define VERSION_REVISION_STR "1"

#define STR_CONST(str) str, (sizeof(str)-1)
#define VEC_CONST(vec) vec, sizeof(vec)
#define CLEAR_VECTOR(vec) memset(vec, 0, sizeof(vec));
#define COMPARE_VECTORS(vec1, vec2) is_vec_content_eq(vec1, sizeof(vec1), vec2, sizeof(vec2))

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
void TEST_encryption_aes_256_destroy(struct test_encryption_aes_256_t **);

int main(int argc, char **argv)
{
  struct test_encryption_aes_256_t *encryption_test;
  TITLE_MSG("Initializing tests")

  C_ASSERT_EQUAL_STRING(
    VERSION_MAJOR_STR"."VERSION_MINOR_STR"."VERSION_REVISION_STR,
    get_version_str(),
    CTEST_SETTER(
      CTEST_TITLE("Check Nakamoto version ...")
    )
  )

  TEST_check_digest();
  TEST_entropy();
  TEST_generate_random_pass();
  encryption_test = TEST_encryption_aes_256();
  TEST_decryption_aes_256(encryption_test);
  TEST_encryption_aes_256_destroy(&encryption_test);

  end_tests();
  return 0;
}

void TEST_check_digest() {
  int err;
  uint8_t sha512[64];
  char *errMsg;
#define DIGEST_MESSAGE "test pointer\x0A"
  //sha512sum_check = echo "test pointer" | sha512sum
  uint8_t sha512sum_check[] = {
    0xda, 0x28, 0xeb, 0x1a, 0xc5, 0xe0, 0x56, 0xbd,
    0x2d, 0x74, 0x90, 0x90, 0x9b, 0xe5, 0xe2, 0x02,
    0xe7, 0xea, 0x1d, 0x91, 0xb5, 0xd4, 0x31, 0x20,
    0xe9, 0x3f, 0x38, 0xe0, 0xaf, 0xf1, 0xe9, 0x7b,
    0xf2, 0x3d, 0xc5, 0xa4, 0x0b, 0xc5, 0x43, 0xa6,
    0x7e, 0x89, 0x96, 0x61, 0x0c, 0x35, 0xa1, 0x15,
    0x10, 0x64, 0x70, 0x93, 0xd6, 0x5f, 0xa8, 0x0b,
    0xce, 0x8f, 0x07, 0x52, 0x41, 0x1f, 0xbe, 0xdf
  };

  CLEAR_VECTOR(sha512)

  err=ssl_hash512(sha512, (uint8_t *)STR_CONST(DIGEST_MESSAGE), &errMsg);

  C_ASSERT_EQUAL_INT(0, err, CTEST_SETTER(
    CTEST_TITLE("Testing ssl_hash512() FIRST TEST"),
    CTEST_INFO("Return value SHOULD be 0"),
    CTEST_ON_ERROR("Was expected value equal 0. Error message: %s", errMsg),
    CTEST_ON_SUCCESS("Success with message: %s", errMsg)
  ))

  TITLE_MSG("Testing CHECK SHA 512 digest below is correct ...")
  debug_dump(sha512, sizeof(sha512));

  C_ASSERT_TRUE(COMPARE_VECTORS(sha512sum_check, sha512), CTEST_SETTER(
    CTEST_TITLE("Testing ssl_hash512("DIGEST_MESSAGE") and compare to sha512sum_check vector ..."),
    CTEST_INFO("Return value SHOULD be TRUE"),
    CTEST_ON_ERROR("Was expected value equal."),
    CTEST_ON_SUCCESS("Success. Vectors are equals")
  ))

  err=check_hash512(sha512sum_check, (uint8_t *)STR_CONST(DIGEST_MESSAGE), &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Testing %p for success HASH message", errMsg),
   CTEST_INFO("Pointer string value SHOULD be not NULL")
  ))

  C_ASSERT_EQUAL_STRING("Checksum SUCCESS\n", errMsg, CTEST_SETTER(
   CTEST_TITLE("Testing successful hash message")
  ))

  C_ASSERT_TRUE(err != 0, CTEST_SETTER(
    CTEST_TITLE("Testing check_hash512 with correct digest message..."),
    CTEST_INFO("Return value SHOULD be NOT EQUAL ZERO (%d)", err),
    CTEST_ON_ERROR("Was unexpected: value equal zero"),
    CTEST_ON_SUCCESS("Success. Return = %d \n%s", err, errMsg)
  ))

  err=check_hash512(sha512sum_check, (uint8_t *)STR_CONST(DIGEST_MESSAGE"_ABC"), &errMsg);
#undef DIGEST_MESSAGE

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Testing %p for not success HASH message", errMsg),
   CTEST_INFO("Pointer string value SHOULD be not NULL")
  ))

  C_ASSERT_EQUAL_STRING("Wrong checksum\n", errMsg, CTEST_SETTER(
   CTEST_TITLE("Testing NOT successful hash message")
  ))

  C_ASSERT_TRUE(err == 0, CTEST_SETTER(
    CTEST_TITLE("Testing check_hash512 with incorrect digest message..."),
    CTEST_INFO("Return value SHOULD be EQUAL ZERO (%d)", err),
    CTEST_ON_ERROR("Was unexpected: value not equal zero"),
    CTEST_ON_SUCCESS("Success. Return = %d\n%s", err, errMsg)
  ))
}

#define TEST_TYPE_NAME(type) {#type, type}
  struct test_entropy_t {
    const char *name;
    uint32_t type;
  } TEST_ENTROPY_TYPE[] = {
    TEST_TYPE_NAME(F_ENTROPY_TYPE_NOT_RECOMENDED),
    TEST_TYPE_NAME(F_ENTROPY_TYPE_GOOD),
    TEST_TYPE_NAME(F_ENTROPY_TYPE_EXCELENT),
    TEST_TYPE_NAME(F_ENTROPY_TYPE_PARANOIC),
    {NULL}
  };
#undef TEST_TYPE_NAME

#define MAX_TIMEOUT_IN_SECOND 16

void TEST_entropy_destroy(void *ctx)
{
  free(ctx);
  close_random();
}

void TEST_entropy()
{
  uint8_t *random_values;
  size_t random_values_size_aligned;
  uint64_t wait_time;
  int err;

  struct test_entropy_t *tep = TEST_ENTROPY_TYPE;

  TITLE_MSG("Begin entropy test")
  INFO_MSG("Opening random ...")

  open_random(NULL);

#define FIRST_VALUE_SIZE 56
  random_values=(uint8_t *)n_malloc(&random_values_size_aligned, FIRST_VALUE_SIZE);

  C_ASSERT_NOT_NULL(random_values, CTEST_SETTER(
   CTEST_TITLE("Testing n_malloc to alloc pointer %p with size %lu bytes", random_values, random_values_size_aligned),
   CTEST_INFO("Return value SHOULD be not NULL")
  ))

  C_ASSERT_TRUE(random_values_size_aligned > FIRST_VALUE_SIZE, CTEST_SETTER(
   CTEST_TITLE("Check if memory is aligned"),
   CTEST_INFO("Value %lu bytes with aligned size %lu bytes", FIRST_VALUE_SIZE, random_values_size_aligned),
   CTEST_ON_ERROR_CB(TEST_entropy_destroy, (void *)random_values)
  ))

  free(random_values);
#undef FIRST_VALUE_SIZE

#define SECOND_VALUE_SIZE 1024
  random_values=(uint8_t *)n_malloc(&random_values_size_aligned, SECOND_VALUE_SIZE);

  C_ASSERT_NOT_NULL(random_values, CTEST_SETTER(
   CTEST_TITLE("Testing n_malloc to second alloc pointer %p with size %lu bytes", random_values, random_values_size_aligned),
   CTEST_INFO("Return value SHOULD be not NULL")
  ))

  C_ASSERT_TRUE(random_values_size_aligned == SECOND_VALUE_SIZE, CTEST_SETTER(
   CTEST_TITLE("Check if memory is aligned (SECOND TEST)"),
   CTEST_INFO("Value %lu bytes with aligned size %lu bytes (SECOND TEST)", SECOND_VALUE_SIZE, random_values_size_aligned),
   CTEST_ON_ERROR_CB(TEST_entropy_destroy, (void *)random_values)
  ))
#undef SECOND_VALUE_SIZE

  INFO_MSG_FMT("Cleaning vector random_values at (%p) with size %lu bytes", random_values, random_values_size_aligned)
  memset(random_values, 0, random_values_size_aligned);
  debug_dump(random_values, random_values_size_aligned);

  while (tep->name) {
    wait_time = 1;

system_entropy_ret:

    INFO_MSG_FMT("Testing entropy %s with random number generator with timeout %lu s ...", tep->name, wait_time)

    err=verify_system_entropy(tep->type, random_values, random_values_size_aligned, wait_time);

    if ((err != 0) && (wait_time < MAX_TIMEOUT_IN_SECOND)) {
      WARN_MSG_FMT("verify_system_entropy %s error %d. Trying new timeout %lu", tep->name, err, ++wait_time)
      goto system_entropy_ret;
    }

    C_ASSERT_TRUE(err == 0, CTEST_SETTER(
     CTEST_TITLE("Check if entropy %s has SUCCESS", tep->name),
     CTEST_ON_ERROR("Check entropy %s. Return error : %d MAX_TIMEOUT_IN_SECOND = %lu s reached", tep->name, err, MAX_TIMEOUT_IN_SECOND),
     CTEST_ON_SUCCESS("Entropy %s success", tep->name),
     CTEST_ON_ERROR_CB(TEST_entropy_destroy, (void *)random_values)
    ))

    INFO_MSG_FMT("Vector random_values at (%p) with size %lu bytes with random data:", random_values, random_values_size_aligned)
    debug_dump(random_values, random_values_size_aligned);
    tep++;
  }

  TEST_entropy_destroy((void *)random_values);
}

void TEST_generate_random_pass_destroy(void *ctx)
{
  pass_list_free((struct pass_list_t **)ctx);
  close_random();
}

void TEST_generate_random_pass()
{
  int err;
  uint8_t wait_time;
  struct test_entropy_t *tep = TEST_ENTROPY_TYPE;

#define PASS_LIST_NUM 50
  struct pass_list_t *pass_list = pass_list_new(PASS_LIST_NUM);

  TITLE_MSG("Begin generate random password ...")

  open_random(NULL);

  C_ASSERT_NOT_NULL(pass_list, CTEST_SETTER(
   CTEST_TITLE("Testing pass_list is not NULL"),
   CTEST_INFO("Return value SHOULD be not NULL")
  ))
#undef PASS_LIST_NUM

  while (tep->name) {
    wait_time=1;

    INFO_MSG_FMT("Testing pass list %s with random number generator with timeout %lu s ...", tep->name, wait_time)

generate_random_pass_ret:
    err = randomize_and_print_pass_list(pass_list, tep->type, wait_time);

    printf("\n\n");

    if ((err != 0) && (wait_time < MAX_TIMEOUT_IN_SECOND)) {
      WARN_MSG_FMT("Pass list %s error %d. Trying new timeout %lu", tep->name, err, ++wait_time)
      goto generate_random_pass_ret;
    }

    C_ASSERT_TRUE(err == 0, CTEST_SETTER(
     CTEST_TITLE("Check if pass list with %s has SUCCESS", tep->name),
     CTEST_ON_ERROR("Check pass list %s fail. Return error : %d MAX_TIMEOUT_IN_SECOND = %lu s reached", tep->name, err, MAX_TIMEOUT_IN_SECOND),
     CTEST_ON_SUCCESS("Pass list %s success", tep->name),
     CTEST_ON_ERROR_CB(TEST_generate_random_pass_destroy, (void *)&pass_list)
    ))

    tep++;
  }

  INFO_MSG_FMT("Destroying pass list (%p)", pass_list)
  pass_list_free(&pass_list);

  C_ASSERT_NULL(pass_list, CTEST_SETTER(
   CTEST_TITLE("Check if pass_list is NULL")
  ))

  WARN_MSG("Testing \"double free\" guard is safe")
  pass_list_free(&pass_list);

  close_random();
}

#undef MAX_TIMEOUT_IN_SECOND

#define PLAIN_TEXT "This Message has more than 16 bytes"
#define IV_TEST "ThisIVHas16Bytes"
#define PRIVATE_KEY_TEST "~This Private Key Has 32 B long~"

_Static_assert((sizeof(PLAIN_TEXT)-1)&0x0F, "PLAIN_TEXT LENGHT MUST BE NOT MULTIPLE OF 16 FOR THIS TEST");
_Static_assert(sizeof(IV_TEST)-1 == 16, "IV_TEST STRING MUST HAVE LENGTH = 16");
_Static_assert(sizeof(PRIVATE_KEY_TEST)-1 == 32, "PRIVATE_KEY_TEST STRING MUST HAVE LENGTH = 32");

void TEST_encryption_aes_256_destroy(struct test_encryption_aes_256_t **ctx)
{
  if (*ctx) {
    free((void *)(*ctx)->encrypted_data);
    free((void *)(*ctx));
    (*ctx) = NULL;
  }
}

struct test_encryption_aes_256_t *TEST_encryption_aes_256()
{
  int err, testNumber = 0;
  char *errMsg;
  uint8_t *buffer;
  uint8_t encryptedData[64];
  size_t encryptedData_size = 0, buffer_size;
  struct test_encryption_aes_256_t *res;

  TITLE_MSG("Begin encryption test AES 256 ...")

  CLEAR_VECTOR(encryptedData);

  err = aes_256_cbc_encrypt(encryptedData, &encryptedData_size, (uint8_t *)STR_CONST(PLAIN_TEXT), (uint8_t *)IV_TEST, (uint8_t *)PRIVATE_KEY_TEST, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -48, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -48. Output pointer encryptedData (%p) with size = 0", encryptedData),
   CTEST_ON_ERROR("Was expected error = -48, but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -48 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Invalid output/input data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description")
    )
  )

  encryptedData_size = sizeof(encryptedData);
  err = aes_256_cbc_encrypt(encryptedData, &encryptedData_size, (uint8_t *)PLAIN_TEXT, 0, (uint8_t *)IV_TEST, (uint8_t *)PRIVATE_KEY_TEST, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -48, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -48. Input pointer plain text (%p) with size = 0", PLAIN_TEXT),
   CTEST_ON_ERROR("Was expected error = -48, but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -48 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Invalid output/input data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description")
    )
  )

  err = aes_256_cbc_encrypt(encryptedData, &encryptedData_size, (uint8_t *)STR_CONST(PLAIN_TEXT), (uint8_t *)IV_TEST, (uint8_t *)PRIVATE_KEY_TEST, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -49, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -49. Check if plain text is aligned (%p)", PLAIN_TEXT),
   CTEST_ON_ERROR("Was expected error = -49 (INPUT NOT ALIGNED IN MEMORY), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -49 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Plain text must be aligned\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: NOT ALIGNED INPUT DATA DESCRIPTION")
    )
  )

  open_random(NULL);
  buffer = (uint8_t *)n_malloc(&buffer_size, sizeof(PLAIN_TEXT));
  close_random();

  C_ASSERT_NOT_NULL(buffer, CTEST_SETTER(
   CTEST_TITLE("Check (%d) buffer (%p) with size is %lu is NOT NULL %p", ++testNumber, buffer)
  ))

  strcpy((char *)buffer, PLAIN_TEXT);
  debug_dump_ascii(buffer, buffer_size);

  encryptedData_size = 10;

  err = aes_256_cbc_encrypt(encryptedData, &encryptedData_size, buffer, buffer_size, (uint8_t *)IV_TEST, (uint8_t *)PRIVATE_KEY_TEST, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  C_ASSERT_TRUE(err == -50, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -50. Check if buffer is greater or equal text plain aligned data size"),
   CTEST_ON_ERROR("Was expected error = -50 (BUFFER HAS NO SIZE TO STORE ENCRYPTED DATA), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -50 success"),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  C_ASSERT_EQUAL_STRING(
    "No space for encrypt data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: BUFFER HAS NO SIZE TO STORE ENCRYPTED DATA"),
      CTEST_ON_ERROR_CB(free, (void *)buffer)
    )
  )

  encryptedData_size = sizeof(encryptedData);
  err = aes_256_cbc_encrypt(encryptedData, &encryptedData_size, buffer, buffer_size, (uint8_t *)IV_TEST, (uint8_t *)PRIVATE_KEY_TEST, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  C_ASSERT_TRUE(err == 0, CTEST_SETTER(
   CTEST_TITLE("Check ENCRYPTED SUCCESS"),
   CTEST_ON_ERROR("Was expected error = 0 (ENCRYPT SUCCESS), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = 0 success"),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  C_ASSERT_EQUAL_STRING(
    "Encrypt SUCCESS\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: ENCRYPT SUCCESS"),
      CTEST_ON_ERROR_CB(free, (void *)buffer)
    )
  )

  C_ASSERT_TRUE(buffer_size == encryptedData_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if encryptedData (%p) size = %lu has same size of plain text buffer (%p) size = %lu",
     ++testNumber, encryptedData, encryptedData_size, buffer, buffer_size),
   CTEST_ON_ERROR("encryptedData_size = %lu and buffer_size = %lu are not equals", encryptedData_size, buffer_size),
   CTEST_ON_SUCCESS("encryptedData_size (%lu) == buffer_size (%lu) success", encryptedData_size, buffer_size),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  C_ASSERT_TRUE(sizeof(encryptedData) >= buffer_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if encryptedData (%p) sizeof(encryptedData) = %lu is greater or equal to encryptedData (%p) size = %lu",
     ++testNumber, encryptedData, sizeof(encryptedData), encryptedData, encryptedData_size),
   CTEST_ON_ERROR("sizeof(encryptedData) = %lu IS LESS THAN encryptedData = %lu size", sizeof(encryptedData), encryptedData_size),
   CTEST_ON_SUCCESS("encryptedData_size (%lu) IS GREATER OR EQUAL buffer_size (%lu) success", sizeof(encryptedData), buffer_size),
   CTEST_ON_ERROR_CB(free, (void *)buffer)
  ))

  INFO_MSG_FMT("ENCRYPTED PLAIN \"%s\". One page", PLAIN_TEXT)
  debug_dump_ascii(encryptedData, encryptedData_size);

  INFO_MSG_FMT("ENCRYPTED PLAIN \"%s\". Full page", PLAIN_TEXT)
  debug_dump_ascii(encryptedData, sizeof(encryptedData));

  free((void *)buffer);

  if ((res = (struct test_encryption_aes_256_t *)malloc(sizeof(struct test_encryption_aes_256_t)))) {
    if ((res->encrypted_data = (uint8_t *)malloc(encryptedData_size))) {
      memcpy(res->iv, IV_TEST, sizeof(res->iv));
      memcpy(res->priv_key, PRIVATE_KEY_TEST, sizeof(res->priv_key));
      memcpy(res->encrypted_data, encryptedData, encryptedData_size);
      res->encrypted_data_size = encryptedData_size;
      res->message = PLAIN_TEXT;
      res-> message_size = sizeof(PLAIN_TEXT);

      return res;
    }

    free(res);
  }

  return NULL;
}

#undef PRIVATE_KEY_TEST
#undef IV_TEST
#undef PLAIN_TEXT

void TEST_decryption_aes_256(struct test_encryption_aes_256_t *ctx)
{
  int err, testNumber = 0;
  uint8_t decryptedData[64];
  size_t decryptedData_size = 0;
  char *errMsg;

  TITLE_MSG("Begin decryption test AES 256 ...")

  C_ASSERT_NOT_NULL(ctx, CTEST_SETTER(
   CTEST_TITLE("Check (%d) encryption context of last test is NOT NULL %p", ++testNumber, ctx)
  ))

  CLEAR_VECTOR(decryptedData);

  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, ctx->encrypted_data_size, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -60, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -60. Output pointer decryptedData (%p) with size = 0", decryptedData),
   CTEST_ON_ERROR("Was expected error = -60, but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -60 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Invalid output/input data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description")
    )
  )

  decryptedData_size = sizeof(decryptedData);
  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, 0, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -60, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -60. Input pointer with encrypted data (%p) with size = 0", ctx->encrypted_data),
   CTEST_ON_ERROR("Was expected error = -60, but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -60 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Invalid output/input data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description")
    )
  )

  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, 1, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -61, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -61. Check if encrypted data is aligned (%p)", ctx->encrypted_data),
   CTEST_ON_ERROR("Was expected error = -61 (DECRYPTION INPUT NOT ALIGNED IN MEMORY), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -61 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Encrypted data must be aligned\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: DECRYPTION INPUT NOT ALIGNED IN MEMORY")
    )
  )

  decryptedData_size = 1;
  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, ctx->encrypted_data_size, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == -62, CTEST_SETTER(
   CTEST_TITLE("Check if HAS ERROR = -62. Check if buffer size is greater or equal encrypted aligned data size"),
   CTEST_ON_ERROR("Was expected error = -62 (BUFFER HAS NO SIZE TO STORE DECRYPTED DATA), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = -62 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "No space for decrypt data\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: BUFFER HAS NO SIZE TO STORE DECRYPTED DATA")
    )
  )

  INFO_MSG("DECRYPTED SCENARIO (STEP 1: Different salt).")
  (*ctx->iv)++;

  decryptedData_size = sizeof(decryptedData);
  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, ctx->encrypted_data_size, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == 0, CTEST_SETTER(
   CTEST_TITLE("Check DECRYPTED SUCCESS"),
   CTEST_ON_ERROR("Was expected error = 0 (DECRYPTED SUCCESS), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = 0 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Decrypt SUCCESS\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: DECRYPTED SUCCESS")
    )
  )

  C_ASSERT_TRUE(sizeof(decryptedData) >= decryptedData_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is less than decrypetedData maximum buffer size = %lu",
     ++testNumber, decryptedData, decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT less or equal to decrypetedData maximum buffer size %lu", decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is less or equal to decrypetedData maximum buffer size %lu success", decryptedData_size, sizeof(decryptedData))
  ))

  INFO_MSG("DECRYPTED PLAIN (STEP 1: Incorrect iv).")
  debug_dump_ascii(decryptedData, decryptedData_size);

  INFO_MSG("DECRYPTED PLAIN (STEP 1: Incorrect iv). Full buffer")
  debug_dump_ascii(decryptedData, sizeof(decryptedData));

  C_ASSERT_TRUE(decryptedData_size >= ctx->message_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is greater or equal than original message size = %lu at pointer (%p)",
     ++testNumber, decryptedData, decryptedData_size, ctx->message_size, ctx->message),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT greater or equal than original message size = %lu", decryptedData_size, ctx->message_size),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is greater or equal to original message size %lu success", decryptedData_size, ctx->message_size)
  ))

  C_ASSERT_TRUE(!is_vec_content_eq((uint8_t *)ctx->message, ctx->message_size, decryptedData, ctx->message_size), CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) is NOT equal to original message (%p)", ++testNumber, decryptedData, ctx->message),
   CTEST_ON_ERROR("decryptedData equal than original message size with wrong iv"),
   CTEST_ON_SUCCESS("Original message NOT equal to decrypted data with wrong iv. Success")
  ))

  INFO_MSG("DECRYPTED SCENARIO (STEP 2: Different salt and wrong private key).")
  (*ctx->priv_key)++;

  decryptedData_size = sizeof(decryptedData);
  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, ctx->encrypted_data_size, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == 0, CTEST_SETTER(
   CTEST_TITLE("Check DECRYPTED SUCCESS"),
   CTEST_ON_ERROR("Was expected error = 0 (DECRYPTED SUCCESS), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = 0 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Decrypt SUCCESS\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: DECRYPTED SUCCESS")
    )
  )

  C_ASSERT_TRUE(sizeof(decryptedData) >= decryptedData_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is less than decrypetedData maximum buffer size = %lu",
     ++testNumber, decryptedData, decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT less or equal to decrypetedData maximum buffer size %lu", decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is less or equal to decrypetedData maximum buffer size %lu success", decryptedData_size, sizeof(decryptedData))
  ))

  INFO_MSG("DECRYPTED PLAIN (STEP 2: Incorrect iv and private key).")
  debug_dump_ascii(decryptedData, decryptedData_size);

  INFO_MSG("DECRYPTED PLAIN (STEP 2: Incorrect iv and private key). Full buffer")
  debug_dump_ascii(decryptedData, sizeof(decryptedData));

  C_ASSERT_TRUE(decryptedData_size >= ctx->message_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is greater or equal than original message size = %lu at pointer (%p)",
     ++testNumber, decryptedData, decryptedData_size, ctx->message_size, ctx->message),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT greater or equal than original message size = %lu", decryptedData_size, ctx->message_size),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is greater or equal to original message size %lu success", decryptedData_size, ctx->message_size)
  ))

  C_ASSERT_TRUE(!is_vec_content_eq((uint8_t *)ctx->message, ctx->message_size, decryptedData, ctx->message_size), CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) is NOT equal to original message (%p)", ++testNumber, decryptedData, ctx->message),
   CTEST_ON_ERROR("decryptedData equal than original message size with wrong iv and private key"),
   CTEST_ON_SUCCESS("Original message NOT equal to decrypted data with wrong iv and private key. Success")
  ))

  INFO_MSG("DECRYPTED SCENARIO (STEP 3: Correct salt and private key).")
  (*ctx->iv)--;
  (*ctx->priv_key)--;

  decryptedData_size = sizeof(decryptedData);
  err = aes_256_cbc_decrypt(
    decryptedData, &decryptedData_size, ctx->encrypted_data, ctx->encrypted_data_size, ctx->iv, ctx->priv_key, &errMsg);

  C_ASSERT_NOT_NULL(errMsg, CTEST_SETTER(
   CTEST_TITLE("Check (%d) errMsg is NOT NULL %p", ++testNumber, errMsg)
  ))

  C_ASSERT_TRUE(err == 0, CTEST_SETTER(
   CTEST_TITLE("Check DECRYPTED SUCCESS"),
   CTEST_ON_ERROR("Was expected error = 0 (DECRYPTED SUCCESS), but found error = %d", err),
   CTEST_ON_SUCCESS("Error = 0 success")
  ))

  C_ASSERT_EQUAL_STRING(
    "Decrypt SUCCESS\n",
    errMsg,
    CTEST_SETTER(
      CTEST_TITLE("Check errMsg error description must contain: DECRYPTED SUCCESS")
    )
  )

  C_ASSERT_TRUE(sizeof(decryptedData) >= decryptedData_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is less than decrypetedData maximum buffer size = %lu",
     ++testNumber, decryptedData, decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT less or equal to decrypetedData maximum buffer size %lu", decryptedData_size, sizeof(decryptedData)),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is less or equal to decrypetedData maximum buffer size %lu success", decryptedData_size, sizeof(decryptedData))
  ))

  INFO_MSG("DECRYPTED PLAIN (STEP 3: Correct iv and private key).")
  debug_dump_ascii(decryptedData, decryptedData_size);

  INFO_MSG("DECRYPTED PLAIN (STEP 3: Correct iv and private key). Full buffer")
  debug_dump_ascii(decryptedData, sizeof(decryptedData));

  C_ASSERT_TRUE(decryptedData_size >= ctx->message_size, CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) size = %lu is greater or equal than original message size = %lu at pointer (%p)",
     ++testNumber, decryptedData, decryptedData_size, ctx->message_size, ctx->message),
   CTEST_ON_ERROR("decryptedData_size = %lu is NOT greater or equal than original message size = %lu", decryptedData_size, ctx->message_size),
   CTEST_ON_SUCCESS("decryptedData_size (%lu) is greater or equal to original message size %lu success", decryptedData_size, ctx->message_size)
  ))

  C_ASSERT_TRUE(is_vec_content_eq((uint8_t *)ctx->message, ctx->message_size, decryptedData, ctx->message_size), CTEST_SETTER(
   CTEST_TITLE("Check (%d) if decryptedData (%p) is equal to original message (%p)", ++testNumber, decryptedData, ctx->message),
   CTEST_ON_ERROR("decryptedData NOT equal than original message size"),
   CTEST_ON_SUCCESS("Original message \"%s\" at pointer %p and decrypted data \"%s\" at pointer %p are equals. Success",
     ctx->message, ctx->message, (char *)decryptedData, decryptedData)
  ))
}

