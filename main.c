#include <stdio.h>
#include <rnd.h>
#include <stdlib.h>
#include <logger.h>
#include <nakamoto.h>
#include <string.h>

#define GEN_RAND_PWD 1<<0
#define INVALID_ENC 1<<1
#define INVALID_DEC 1<<2
#define ENC 1<<3
#define DEC 1<<4
#define NUM_OF_PASSWORD 50
#define ENTROPY_TIMEOUT 60

int main(int argc, char **argv)
{
  int err, option;
  char *v;
  struct pass_list_t *pass_list;
  struct file_util_t *file_util;
  struct pass_t *pass;

  if (argc==1) {
ret_1:
    N_INFOF(
      "\nVersion: %s"
      "\nUsage:\n\thelp - Show this help\n\tg - Generate random passwords\n\tenc <filename> - Encrypt file\n\tdec <encrypted filename> - Decrypt file\n",
      get_version_str()
    );
    return 0;
  }

  if (argc==2) {
    if (!strcmp(v=argv[1], "help"))
      goto ret_1;

    if (!strcmp(v, "g"))
      option=GEN_RAND_PWD;
    else if (!strcmp(v, "enc"))
      option=INVALID_ENC;
    else if (!strcmp(v, "dec"))
      option=INVALID_DEC;
    else {
ret_2:
      N_INFOF("\nInvalid parameter %s\n", v);
      return -1;
    }
  } else if (argc==3) {
    if (!strcmp(v=argv[1], "enc"))
      option=ENC;
    else if (!strcmp(v, "dec"))
      option=DEC;
    else
      goto ret_2;

    v=argv[2];

  } else {
    N_INFO("\n\tToo many arguments\n");
    return -2;
  }

  if (option&INVALID_ENC) {
    N_INFO("Missing plain text filename\n")
    return -3;
  }

  if (option&INVALID_DEC) {
    N_INFO("Missing encrypted filename\n")
    return -4;
  }

  open_random(NULL);

  if (option&GEN_RAND_PWD) {
    N_INFOF(
      "Generating %d random passwords with high entropy. Move your mouse, play a music in your computer, open a browser to increase entropy"
      "\n... Wait generating random passwords ...\n",
      NUM_OF_PASSWORD
    )
    N_INFO("")
    if (!(pass_list=pass_list_new(NUM_OF_PASSWORD))) {
      err=-5;
      N_ERROR("\nError pass_list_new. Try again\n")
      goto exit_1;
    }

    if ((err=randomize_and_print_pass_list(pass_list, F_ENTROPY_TYPE_PARANOIC, ENTROPY_TIMEOUT)))
      N_ERRORF("\nError randomize_and_print_pass_list %d. Try again", err);

    pass_list_free(&pass_list);

  } else if (option&ENC) {
    N_INFO(
      "Generating random number with high entropy. Move your mouse, play a music in your computer, open a browser to increase entropy"
      "\n... Wait generating random numbers ...\n"
    )
    N_INFO("")
    if (!(file_util=WRITE_begin_header(ENTROPY_TIMEOUT))) {
      err=-6;
      N_ERROR("\nError begin encrypt write. Try again\n")
      goto exit_1;
    }

    N_INFOF("Begin encryption ...\n... Wait a little longer to encrypt file %s ...\n", v)
    N_INFO("")

    if (!(err=set_password(&pass))) {
      if ((err=WRITE_derive_keys(file_util, pass->passwd, v)))
        N_ERRORF("WRITE_derive_keys %d\n", err)

      pass_free(&pass);
    }

    WRITE_end_header(&file_util);

  } else {

    N_INFOF("Begin decryption \n... Wait a little long to decrypt file %s ...\n", v)
    N_INFO("")

    if (!(file_util=READ_begin_header())) {
      err=-2;
      N_ERROR("\nError begin decrypt read. Try again\n")
      goto exit_1;
    }

    if (!(err=get_password(&pass))) {
      if ((err=READ_extract(file_util, pass->passwd, v)))
        N_ERRORF("READ_extract file %s. Try again. Maybe wrong password or corrupted file - %d", v, err)

      pass_free(&pass);
    }

    READ_end_header(&file_util);

  }

exit_1:

  close_random();

  if (err)
    N_ERRORF("Fail with error %d\n", err)
  else
    N_INFO("SUCCESS\n")

  return err;
}

