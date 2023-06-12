#ifndef RND_H
 #define RND_H

#include <stdint.h>
#include <stddef.h>

int gen_rand_no_entropy_util(uint8_t *, size_t);

int verify_system_entropy(
  uint32_t,
  uint8_t *,
  size_t,
  uint64_t
);

void open_random(char *);

void close_random();

#define PASS_SZ 38
struct pass_list_vec_t {
  char password[PASS_SZ];
};
#undef PASS_SZ
struct pass_list_t {
  uint16_t n; // Number of vectors;
  size_t vec_size; // In bytes
  struct pass_list_vec_t *vec; // Vector. MUST be free
};

/**
 * @def F_ENTROPY_TYPE_PARANOIC
 * @brief Type of the very excelent entropy used for verifier. Very slow
 */
#define F_ENTROPY_TYPE_PARANOIC (uint32_t)1477682819

//#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1475885281
/**
 * @def F_ENTROPY_TYPE_EXCELENT
 * @brief Type of the excelent entropy used for verifier. Slow
 */
#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1476885281

//#define F_ENTROPY_TYPE_GOOD (uint32_t)1471531015
/**
 * @def F_ENTROPY_TYPE_GOOD
 * @brief Type of the good entropy used for verifier. Not so slow
 */
#define F_ENTROPY_TYPE_GOOD (uint32_t)1472531015

//#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1470001808
/**
 * @def F_ENTROPY_TYPE_NOT_ENOUGH
 * @brief Type of the moderate entropy used for verifier. Fast
 */
#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1471001808

//#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1469703345
/**
 * @def F_ENTROPY_TYPE_NOT_RECOMENDED
 * @brief Type of the not recommended entropy used for verifier. Very fast
 */
#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1470003345

struct pass_list_t *pass_list_new(uint16_t);
int randomize_and_print_pass_list(struct pass_list_t *, uint32_t, uint64_t);
void pass_list_free(struct pass_list_t **);

#endif
