#include "testutil.h"

int main(int argc, char **argv)
{
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
  TEST_decryption_aes_256(
    TEST_encryption_aes_256()
  );
  TEST_password_strength();
  TEST_pbkdf2();

  end_tests();
  return 0;
}

