#include <test/asserts.h>
#include <logger.h>
#include <nakamoto.h>

#define VERSION_MAJOR_STR "0"
#define VERSION_MINOR_STR "1"
#define VERSION_REVISION_STR "1"

#define STR_CONST(str) str, (sizeof(str)-1)

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

  TITLE_MSG("Testing CHECK SHA 512 digest ...")

  err=ssl_hash512(sha512, (uint8_t *)STR_CONST("test pointer\x0A"), &errMsg);

  debug_dump(sha512, sizeof(sha512));

  C_ASSERT_EQUAL_INT(0, err, CTEST_SETTER(
    CTEST_TITLE("Testing ssl_hash512() FIRST TEST"),
    CTEST_INFO("Return value SHOULD be 0"),
    CTEST_ON_ERROR("Was expected value equal -26. Error message: %s", errMsg),
    CTEST_ON_SUCCESS("Success with message: %s", errMsg)
  ))

}
