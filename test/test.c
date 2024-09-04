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
#define CLEAR_VECTOR(vec) memset(vec, 0, sizeof(vec));
#define COMPARE_VECTORS(vec1, vec2) is_vec_content_eq(vec1, sizeof(vec1), vec2, sizeof(vec2))

void TEST_check_digest();
void TEST_entropy();
void TEST_entropy_destroy();

int main(int argc, char **argv)
{
  TITLE_MSG("Initializing tests")

  C_ASSERT_EQUAL_STRING_IGNORE_CASE(
    VERSION_MAJOR_STR"."VERSION_MINOR_STR"."VERSION_REVISION_STR,
    get_version_str(),
    CTEST_SETTER(
      CTEST_TITLE("Check Nakamoto version ...")
    )
  )

  TEST_check_digest();
  TEST_entropy();

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

}

void TEST_entropy()
{
  uint8_t *random_values;
  size_t random_values_size_aligned;
  uint64_t wait_time;
  int err;

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

  struct test_entropy_t *tep = TEST_ENTROPY_TYPE;
#undef TEST_TYPE_NAME

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
   CTEST_ON_ERROR_CB(free, (void *)random_values)
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
   CTEST_ON_ERROR_CB(free, (void *)random_values)
  ))
#undef SECOND_VALUE_SIZE

  INFO_MSG_FMT("Cleaning vector random_values at (%p) with size %lu bytes", random_values, random_values_size_aligned)
  memset(random_values, 0, random_values_size_aligned);
  debug_dump(random_values, random_values_size_aligned);

  while (tep->name) {
    wait_time = 1;

system_entropy_ret:
#define MAX_TIMEOUT_IN_SECOND 12

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
     CTEST_ON_ERROR_CB(free, (void *)random_values)
    ))

#undef MAX_TIMEOUT_IN_SECOND

    INFO_MSG_FMT("Vector random_values at (%p) with size %lu bytes with random data:", random_values, random_values_size_aligned)
    debug_dump(random_values, random_values_size_aligned);
    tep++;
  }
  free(random_values);

  close_random();
}

void TEST_entropy_destroy() {

}
