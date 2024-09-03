#ifndef UTILITY_H
  #define UTILITY_H

#include <nakamoto.h>
#include <stddef.h>
#include <stdint.h>

#define CONST_STR_LEN(s) sizeof(s)-1
#define FILE_BUFFER_SIZE (size_t)1*1024*1024 // 1 MB max
_Static_assert((FILE_BUFFER_SIZE&0x0F)==0, "FILE_BUFFER_SIZE must be 16 byte alingned");

uint32_t setU32_LE(uint32_t);
uint64_t setU64_LE(uint64_t);
int writeToFile(const char *, uint8_t *, size_t);
int ssl_hash512(uint8_t *, uint8_t *, size_t, char **);
int pbkdf2(
  uint8_t *, size_t,
  const char *, int,
  uint8_t *, uint32_t,
  uint32_t,
  char **
);
int argon2id(
  uint8_t *, size_t,
  const char *, int,
  uint8_t *, uint32_t,
  uint8_t *, uint32_t, //Optional. can be null
  uint8_t *, uint32_t, //Optional. can be null
  uint32_t,
  uint32_t,
  uint32_t,
  char **
);

int aes_256_cbc_encrypt(
  uint8_t *, size_t *,
  uint8_t *, size_t,
  uint8_t *, uint8_t *,
  char **
);

int aes_256_cbc_decrypt(
  uint8_t *, size_t *,
  uint8_t *, size_t,
  uint8_t *, uint8_t *,
  char **
);
int check_hash512(uint8_t *, uint8_t *, size_t, char **);

int readFileAlign(uint8_t **, size_t *, size_t *, const char *);
int readFileAlignDecrypt(uint8_t **, size_t *, size_t *, const char *);
void readFileAlignFree(uint8_t **, size_t);

int writeFileUtil(const char *, uint8_t *, size_t);

uint8_t *xor_n(uint8_t *, uint8_t *, size_t);

struct pass_t {
//  size_t len;
  char passwd[MAX_PASSWD+1];
  char retype_passwd[MAX_PASSWD+1];
};

int set_password(struct pass_t **);
int get_password(struct pass_t **);
void pass_free(struct pass_t **);

char *get_version_str();

#ifdef VISIBLE_FOR_TEST
void *n_malloc(size_t *, size_t);
#endif

#endif

