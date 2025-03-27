#ifndef NAKAMOTO_H
 #define NAKAMOTO_H

#define N_MAX 65
#define MIN_PASSWD 16
#define MAX_PASSWD (N_MAX-1)

#include <utility.h>
//dom 23 abr 2023 14:50:07 

#define VERSION_MAJOR 0
#define VERSION_MINOR 1
#define VERSION_REVISION 4
#define GET_VER_MAJ(val) (val>>20)
#define GET_VER_MIN(val) ((val>>10)&0x03FF)
#define GET_VER_REV(val) (val&0x03FF)
#define NAKAMOTO_VERSION(major, minor, revision) (uint32_t)((major<<20)|(minor<<10)|(revision))
#define NAKAMOTO_VERSION_SET NAKAMOTO_VERSION(VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION)
#define INTERACTION 8*1024*1024
#define FILE_BUFFER_SIZE (size_t)1*1024*1024 // 1 MB max
#define FILE_STRUCT_SIZE (sizeof(struct file_struct_t) + sizeof(struct cipher_block_t) + sizeof(struct cipher_block_data_t))

#define NAKAMOTO "nakamoto"

//decrypted by key 1 and key 2
struct cipher_block_data_t {
  uint8_t hash_xored_restore[64]; // Salt used to invert logic of hash_xored. if hash_xored_restore^hash_xored = hash512(unencrypted(data))
  uint64_t file_size; // Original file size in little endian
  uint8_t pad[8]; //Padding
  //Below is data of ALIGN(file_size) encrypted by key1 and key2
  //uint8_t *data
} __attribute__ ((packed));

_Static_assert((sizeof(struct cipher_block_data_t)&0x0F)==0, "struct cipher_block_data_t MUST have size multiple of 16");

//decrypted by key 1
struct cipher_block_t {
//  uint32_t memory_cost;
//  uint32_t interaction_cost;
//  uint32_t parallel_cost;
//  uint8_t pad[4+4+4+4];
  uint8_t additional[32];
  uint8_t secret[32];
  uint8_t iv2[16]; // Initial vector from private key 2
  uint8_t hash_xored[64]; //Xor'ed or with hash512 of the file. It will be the salt2 of the pbkdf2 step 2 to derive second private key.
} __attribute__ ((packed));

_Static_assert((sizeof(struct cipher_block_t)&0x0F)==0, "struct cipher_block_t MUST have size multiple of 16");

struct file_struct_t {
  char magic[CONST_STR_LEN(NAKAMOTO)]; // Magic
  uint32_t version; // Version in Little endian
//  uint32_t iteraction; // Interaction for pbkdf2 in little endian
  uint8_t pad[4];
  uint8_t iv1[16]; //Initial vector of the private key 1 derived from password
  uint8_t salt1[64]; //Initial salt from private key 1
  char description[48]; // Brief description in header
  uint8_t sha512[64]; //Hash 512 of this header file_struct_t
} __attribute__ ((packed));

struct file_util_t {
/*
  uint8_t iv1_tmp[16]; //IV1 temp for OpenSSL
  uint8_t iv2_tmp[16]; // IV2 temp for OpenSSL
  */
  uint8_t priv_key1[32]; // Private key1 for encrypt/decrypt data
  uint8_t priv_key2[32]; // Private key2 for encrypt/decrypt data
  struct file_struct_t *file_struct; // Structure of the file. Must be free
  uint8_t *_file_buffer; //Buffer of file. It must be free
};

_Static_assert((sizeof(struct file_struct_t)&0x0F)==0, "struct file_struct_t MUST have size multiple of 16");

struct file_util_t *WRITE_begin_header(uint64_t);
void WRITE_end_header(struct file_util_t **);

int WRITE_derive_keys(struct file_util_t *, const char *, const char *);

struct file_util_t *READ_begin_header();
int READ_extract(struct file_util_t *, const char *, const char *);
void READ_end_header(struct file_util_t **);

#define CIPHER_INFO_SZ sizeof(struct cipher_block_t)+sizeof(struct cipher_block_data_t)
_Static_assert(FILE_BUFFER_SIZE>CIPHER_INFO_SZ, "CIPHER_INFO_SZ is less than FILE_BUFFER_SIZE");

#define FILE_STRUCT_DATA_HASH_SZ sizeof(struct file_struct_t)-sizeof(((struct file_struct_t *)0)->sha512)

/**
 * @def PASS_MUST_HAVE_AT_LEAST_NONE
 * @brief Password does not need any criteria to pass
 */
#define PASS_MUST_HAVE_AT_LEAST_NONE (int)0

/**
 * @def PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER
 * @brief Password must have at least one number
 */
#define PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER (int)1

/**
 * @def PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL
 * @brief Password must have at least one symbol
 */
#define PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL (int)2

/**
 * @def PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE
 * @brief Password must have at least one upper case
 */
#define PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE (int)4

/**
 * @def PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE
 * @brief Password must have at least one lower case
 */
#define PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE (int)8

/**
 * @def PASS_IS_TOO_LONG
 * @brief Password is too long
 */
#define PASS_IS_TOO_LONG (int)256

/**
 * @def PASS_IS_TOO_SHORT
 * @brief Password is too short
 */
#define PASS_IS_TOO_SHORT (int)512

/**
 * @def PASS_IS_OUT_OVF
 * @brief Password is overflow and cannot be stored
 */
#define PASS_IS_OUT_OVF (int)1024//768

/**
 * @def PASS_IS_NULL
 * @brief Password is NULL
 */
#define PASS_IS_NULL (int)2048//768

#define MUST_HAVE (PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER|PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL|PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE| \
  PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)

#ifdef VISIBLE_FOR_TEST
uint32_t getArgon2idMemCost();
uint32_t getArgon2idInteractionCost();
uint32_t getArgon2idParallelCost();
int pass_must_have_at_least(size_t *, char *, size_t, size_t, size_t, int);
#endif

#endif

