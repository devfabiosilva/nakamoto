#include <test/asserts.h>
#include <logger.h>
#include <nakamoto.h>
#include <string.h>

#define VERSION_MAJOR_STR "0"
#define VERSION_MINOR_STR "1"
#define VERSION_REVISION_STR "1"

#define STR_CONST(str) str, (sizeof(str)-1)
#define CLEAR_VECTOR(vec) memset(vec, 0, sizeof(vec));
#define COMPARE_VECTORS(vec1, vec2) is_vec_content_eq(vec1, sizeof(vec1), vec2, sizeof(vec2))

void TEST_check_digest();

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

