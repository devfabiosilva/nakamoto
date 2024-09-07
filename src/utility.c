#include <nakamoto.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <rnd.h>
#include <logger.h>
#include <openssl/thread.h>
#include <termios.h>
#include <unistd.h>

#ifdef BE
uint32_t setU32_LE(uint32_t value)
{
  N_DEBUG("setU32_LE : (BIG ENDIAN)")
  union val_u {
    uint8_t u8[sizeof(uint32_t)];
    uint32_t u32;
  } val;
  uint8_t u8_tmp;

  val.u32=value;

  u8_tmp=val.u8[0];
  val.u8[0]=val.u8[3];
  val.u8[3]=u8_tmp;

  u8_tmp=val.u8[1];
  val.u8[1]=val.u8[2];
  val.u8[2]=u8_tmp;

  return val.u32;
}

uint64_t setU64_LE(uint64_t value)
{
  N_DEBUG("setU64_LE : (BIG ENDIAN)")
  union val_u {
    uint8_t u8[sizeof(uint64_t)];
    uint64_t u64;
  } val;
  uint8_t u8_tmp;

  val.u64=value;

//0 - 7
//1 - 6
//2 - 5
//3 - 4

  u8_tmp=val.u8[0];
  val.u8[0]=val.u8[7];
  val.u8[7]=u8_tmp;

  u8_tmp=val.u8[1];
  val.u8[1]=val.u8[6];
  val.u8[6]=u8_tmp;

  u8_tmp=val.u8[2];
  val.u8[2]=val.u8[5];
  val.u8[5]=u8_tmp;

  u8_tmp=val.u8[3];
  val.u8[3]=val.u8[4];
  val.u8[4]=u8_tmp;

  return val.u64;
}

#else
 #ifdef LE
inline uint32_t setU32_LE(uint32_t value)
{
  N_DEBUG("setU32_LE : (LITTLE ENDIAN)")
  return value;
}

inline uint64_t setU64_LE(uint64_t value)
{
  N_DEBUG("setU64_LE : (LITTLE ENDIAN)")
  return value;
}
 #else
  #error "Define LE or BE"
 #endif
#endif

int writeToFile(const char *filename, uint8_t *data, size_t data_sz)
{
  int err;
  FILE *f;

  if (!(f=fopen(filename, "w")))
    return -2;

  err=(fwrite((void *)data, sizeof(uint8_t), data_sz, f)==data_sz)?0:-3;

  fclose(f);

  return err;
}

#define SSL_MSG_SET(msg) \
  if (errMsg) \
    *errMsg=msg;

int ssl_hash512(uint8_t *out, uint8_t *data, size_t data_sz, char **errMsg)
{
  OSSL_LIB_CTX *library_context;
  int err;
  EVP_MD *message_digest;
  EVP_MD_CTX *digest_context;
  unsigned int digest_length;

  library_context=OSSL_LIB_CTX_new();
  if (library_context == NULL) {
    SSL_MSG_SET("OSSL_LIB_CTX_new() returned NULL\n");
    return -20;
  }

  /*
   * Fetch a message digest by name
   * The algorithm name is case insensitive. 
   * See providers(7) for details about algorithm fetching
   */
  message_digest=EVP_MD_fetch(library_context, "SHA512", NULL);
  if (message_digest == NULL) {
    err=-21;
    SSL_MSG_SET("EVP_MD_fetch could not find SHA512.")
    goto ssl_hash512_resume1;
  }

  /* Determine the length of the fetched digest type */
  digest_length=EVP_MD_get_size(message_digest);
  if (digest_length != 64) {
    err=-22;
    SSL_MSG_SET("EVP_MD_get_size returned invalid size.\n")
    goto ssl_hash512_resume2;
  }

  /*
   * Make a message digest context to hold temporary state
   * during digest creation
   */
  digest_context = EVP_MD_CTX_new();
  if (digest_context == NULL) {
    err=-24;
    SSL_MSG_SET("EVP_MD_CTX_new failed.\n")
    goto ssl_hash512_resume2;
  }
  /*
   * Initialize the message digest context to use the fetched 
   * digest provider
   */
  if (EVP_DigestInit(digest_context, message_digest) != 1) {
    err=-25;
    SSL_MSG_SET("EVP_DigestInit failed.\n")
    goto ssl_hash512_resume3;
  }
  if (EVP_DigestUpdate(digest_context, (const void *)data, data_sz) != 1) {
    err=-26;
    SSL_MSG_SET("EVP_DigestUpdate(data) failed.\n")
    goto ssl_hash512_resume3;
  }
  if (EVP_DigestFinal(digest_context, (unsigned char *)out, &digest_length) != 1) {
    err=-27;
    SSL_MSG_SET("EVP_DigestFinal() failed.\n")
    goto ssl_hash512_resume3;
  }

  err=0;
  SSL_MSG_SET("Hash 512 success")
  if (digest_length != 64) {
    err=-28;
    SSL_MSG_SET("Hash 512 size error")
  }

ssl_hash512_resume3:
  EVP_MD_CTX_free(digest_context);

ssl_hash512_resume2:
  EVP_MD_free(message_digest);

ssl_hash512_resume1:
  OSSL_LIB_CTX_free(library_context);
  return err;
}

int pbkdf2(
  uint8_t *out, size_t out_sz,
  const char *password, int password_len,
  uint8_t *salt, uint32_t salt_sz,
  uint32_t iter,
  char **errMsg
)
{
  int err;;
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
//    unsigned char out[64];
  OSSL_PARAM params[5], *p;
  OSSL_LIB_CTX *library_context;
  unsigned int pbkdf2_iteration;

  if (!password) {
    SSL_MSG_SET("Null password\n")
    return -30;
  }

  if (password_len < 0)
    password_len=(int)strlen(password);

  if (!password_len) {
    SSL_MSG_SET("Empty password\n")
    return -31;
  }

  library_context=OSSL_LIB_CTX_new();
  if (library_context==NULL) {
    SSL_MSG_SET("OSSL_LIB_CTX_new() returned NULL\n")
    return -32;
  }

  /* Fetch the key derivation function implementation */
  kdf = EVP_KDF_fetch(library_context, "PBKDF2", NULL);
  if (kdf == NULL) {
    err=-33;
    SSL_MSG_SET("EVP_KDF_fetch() returned NULL\n")
    goto pbkdf2_exit1;
  }

  /* Create a context for the key derivation operation */
  kctx = EVP_KDF_CTX_new(kdf);
  if (kctx == NULL) {
    err=-32;
    SSL_MSG_SET("EVP_KDF_CTX_new() returned NULL\n")
    goto pbkdf2_exit2;
  }

  pbkdf2_iteration=(unsigned int)iter;
  p=params;

  /* Set password */
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (unsigned char *)password, (unsigned int)password_len);
  /* Set salt */
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (unsigned char *)salt, (unsigned int)salt_sz);
  /* Set iteration count */
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &pbkdf2_iteration);
  /* Set the underlying hash function used to derive the key */
  *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);

  *p = OSSL_PARAM_construct_end();

  err=0;
  SSL_MSG_SET("PBKDF2-SHA256 success\n")
  /* Derive the key */
  if (EVP_KDF_derive(kctx, (unsigned char *)out, out_sz, params) != 1) {
    err=-33;
    SSL_MSG_SET("EVP_KDF_derive() failed\n")
  }

//    if (CRYPTO_memcmp(expected_output, out, sizeof(expected_output)) != 0) {

  EVP_KDF_CTX_free(kctx);

pbkdf2_exit2:
  EVP_KDF_free(kdf);

pbkdf2_exit1:
  OSSL_LIB_CTX_free(library_context);

  return err;
}

int argon2id(
  uint8_t *out, size_t out_sz,
  const char *password, int password_len,
  uint8_t *salt, uint32_t salt_sz,
  uint8_t *additional, uint32_t additional_sz, //Optional. can be null
  uint8_t *secret, uint32_t secret_sz, //Optional. can be null
  uint32_t memory_cost,
  uint32_t iteration_cost,
  uint32_t parallel_cost,
  char **errMsg
)
{
  int err;
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;

  OSSL_PARAM params[9], *p = params;
  OSSL_LIB_CTX *library_context;
  unsigned int threads, m_cost, i_cost, p_cost;

  if (!password) {
    SSL_MSG_SET("Null password\n")
    return -40;
  }

  if (password_len<0)
    password_len=(int)strlen(password);

  if (!password_len) {
    SSL_MSG_SET("Empty password\n")
    return -41;
  }

  library_context=OSSL_LIB_CTX_new();
  if (library_context == NULL) {
    SSL_MSG_SET("OSSL_LIB_CTX_new() returned NULL\n")
    return -41;
  }

  /* Fetch the key derivation function implementation */
  kdf = EVP_KDF_fetch(library_context, "argon2id", NULL);
  if (kdf == NULL) {
    err=-42;
    SSL_MSG_SET("EVP_KDF_fetch() returned NULL\n")
    goto argon2id_exit1;
  }

  /* Create a context for the key derivation operation */
  kctx = EVP_KDF_CTX_new(kdf);
  if (kctx == NULL) {
    err=-43;
    SSL_MSG_SET("EVP_KDF_CTX_new() returned NULL\n")
    goto argon2id_exit2;
  }

  /*
   * Thread support can be turned off; use serialization if we cannot
   * set requested number of threads.
   */
  threads = (unsigned int)parallel_cost;
  if (OSSL_set_max_threads(library_context, (unsigned int)parallel_cost) != 1) {
    uint64_t max_threads = OSSL_get_max_threads(library_context);

    if (max_threads == 0)
      threads = 1;
    else if (max_threads < parallel_cost)
      threads = (unsigned int)max_threads;
  }

  m_cost=(unsigned int)memory_cost;
  i_cost=(unsigned int)iteration_cost;
  p_cost=(unsigned int)parallel_cost;

  /* Set password */
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (unsigned char *)password, (unsigned int)password_len);
  /* Set salt */
  *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (unsigned char *)salt, (unsigned int)salt_sz);

  /* Set optional additional data */
  if (additional)
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, (unsigned char *)additional, (unsigned int)additional_sz);

  /* Set optional secret */
  if (secret)
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (unsigned char *)secret, (unsigned int)secret_sz);

  /* Set iteration count */
  *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &i_cost);
  /* Set threads performing derivation (can be decreased) */
  *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
  /* Set parallel cost */
  *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &p_cost);
  /* Set memory requirement */
  *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost);
  *p = OSSL_PARAM_construct_end();

  err=0;
  SSL_MSG_SET("Argon2id success\n")

  /* Derive the key */
  if (EVP_KDF_derive(kctx, (unsigned char *)out, (unsigned int)out_sz, params) != 1) {
    err=-44;
    SSL_MSG_SET("EVP_KDF_derive() failed\n")
  }

  EVP_KDF_CTX_free(kctx);

argon2id_exit2:
  EVP_KDF_free(kdf);

argon2id_exit1:
  OSSL_LIB_CTX_free(library_context);

  return err;
}

int aes_256_cbc_encrypt(
  uint8_t *out, size_t *out_size,
  uint8_t *in, size_t in_size,
  uint8_t *iv, uint8_t *priv_key,
  char **errMsg
)
{

  int err;
  EVP_CIPHER_CTX *ctx;
  EVP_CIPHER *cipher;
  //

  if (((*out_size)==0)||(in_size==0)) {
    SSL_MSG_SET("Invalid output/input data\n")
    return -48;
  }

  if (in_size&0x0F) {
    SSL_MSG_SET("Plain text must be aligned\n")
    return -49;
  }

  if (in_size>(*out_size)) {
    SSL_MSG_SET("No space for encrypt data\n")
    return -50;
  }

  /* Create a context for the encrypt operation */
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
    SSL_MSG_SET("Could not init AES context\n")
    return -51;
  }

  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

  /* Fetch the cipher implementation */
  if ((cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL)) == NULL) {
    err=-52;
    SSL_MSG_SET("Could not fetch cipher\n")
    goto aes_256_cbc_encrypt_exit1;
  }

  /*
   * Initialise an encrypt operation with the cipher/mode, key and IV.
   * We are not setting any custom params so let params be just NULL.
   */
  if (!EVP_EncryptInit_ex2(ctx, cipher, (const unsigned char *)priv_key, (const unsigned char *)iv, /* params */ NULL)) {
    err=-53;
    SSL_MSG_SET("Could not init encrypt\n")
    goto aes_256_cbc_encrypt_exit2;
  }

  /* Encrypt plaintext */
  if (!EVP_EncryptUpdate(ctx, (unsigned char *)out, (int *)out_size, (unsigned char *)in, (int)in_size)) {
    err=-54;
    SSL_MSG_SET("Could not update encrypt data\n")
    goto aes_256_cbc_encrypt_exit2;
  }

//  *out_size=in_size;
/*
//NOT NECESSARY if   EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);
// See https://www.openssl.org/docs/man3.1/man3/EVP_EncryptFinal_ex.html
  // Finalise: there can be some additional output from padding /
  if (!EVP_EncryptFinal_ex(ctx, (((unsigned char *)out) + *out_size), &tmp_size)) {
    err=-55;
    SSL_MSG_SET("Could not finalize encrypt data\n")
    goto aes_256_cbc_encrypt_exit2;
  }
*/
  err=0;
  SSL_MSG_SET("Encrypt SUCCESS\n")

aes_256_cbc_encrypt_exit2:
  EVP_CIPHER_free(cipher);

aes_256_cbc_encrypt_exit1:
  EVP_CIPHER_CTX_free(ctx);

  return err;
}

int aes_256_cbc_decrypt(
  uint8_t *out, size_t *out_size,
  uint8_t *in, size_t in_size,
  uint8_t *iv, uint8_t *priv_key,
  char **errMsg
)
{

  int err;
  EVP_CIPHER_CTX *ctx;
  EVP_CIPHER *cipher;

  if (((*out_size)==0)||(in_size==0)) {
    SSL_MSG_SET("Invalid output/input data\n")
    return -60;
  }

  if (in_size&0x0F) {
    SSL_MSG_SET("Encrypted data must be aligned\n")
    return -61;
  }

  if (in_size>(*out_size)) {
    SSL_MSG_SET("No space for decrypt data\n")
    return -62;
  }

  if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
    SSL_MSG_SET("Could not init AES context\n")
    return -63;
  }

  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

  if ((cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL)) == NULL) {
    err=-64;
    SSL_MSG_SET("Could not fetch cipher\n")
    goto aes_256_cbc_decrypt_exit1;
  }

  /*
   * Initialise an encrypt operation with the cipher/mode, key and IV.
   * We are not setting any custom params so let params be just NULL.
   */
  if (!EVP_DecryptInit_ex2(ctx, cipher, (const unsigned char *)priv_key, (const unsigned char *)iv, /* params */ NULL)) {
    err=-64;
    SSL_MSG_SET("Could not init decrypt\n")
    goto aes_256_cbc_decrypt_exit2;
  }

  /* Decrypt plaintext */
  if (!EVP_DecryptUpdate(ctx, (unsigned char *)out, (int *)out_size, (unsigned char *)in, (int)in_size)) {
    err=-65;
    SSL_MSG_SET("Could not update decrypt data\n")
    goto aes_256_cbc_decrypt_exit2;
  }

  err=0;
  SSL_MSG_SET("Decrypt SUCCESS\n")

/*
//NOT NECESSARY if   EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);
// See https://www.openssl.org/docs/man3.1/man3/EVP_EncryptFinal_ex.html
     Finalise: there can be some additional output from padding
    if (!EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen))
        goto err;
    outlen += tmplen;
*/

aes_256_cbc_decrypt_exit2:
  EVP_CIPHER_free(cipher);

aes_256_cbc_decrypt_exit1:
  EVP_CIPHER_CTX_free(ctx);

  return err;
}
#undef SSL_MSG_SET

#define N_ALIGNMENT (size_t)(1<<4)
#define N_ALIGNMENT_MASK (size_t)(N_ALIGNMENT-1)

#define N_ALIGN \
size_t size_tmp=size; \
\
if (size_tmp&(N_ALIGNMENT_MASK)) {\
  size_tmp&=(~N_ALIGNMENT_MASK);\
  size_tmp+=N_ALIGNMENT;\
}

#ifndef VISIBLE_FOR_TEST
static
#endif
void *n_malloc(size_t *size_align, size_t size)
{
  uint8_t *result;
//size_align >= size
  N_ALIGN

  N_DEBUGF("Entering n_malloc. Required size %lu. Alloc'd size: %lu. Offset: %lu", size, size_tmp, size_tmp-size)

  *size_align=size_tmp;

#ifdef DEBUG
  if (size_tmp<size) {
    N_DEBUG("Bad alignment. Refactor")
    return NULL;
  }
#endif

  if ((result=(uint8_t *)malloc(size_tmp))) {
    N_DEBUGF("Alloc'd success at %p", result)
    if ((size_tmp-=size)) {
       N_DEBUGF("Filling offset %lu with random data @ %p", size_tmp, &result[size])
       if (gen_rand_no_entropy_util((uint8_t *)&result[size], size_tmp)) {
         N_DEBUGF("gen_rand_no_entropy_util fail @ n_malloc. Freeing %p", result)
         free((void *)result);
         result=NULL;
       }
#ifdef DEBUG
       else {
         N_DEBUG_DUMP(&result[size], size_tmp)
         N_DEBUGF("Number of random data %lu at %p", size_tmp, &result[size])
       }
#endif
    }
#ifdef DEBUG
    else
      N_DEBUGF("No random data to fill at %p", result)
#endif
  }

  return (void *)result;
}

static
int readFileAlignUtil(uint8_t **data, size_t *data_size, size_t *data_size_align, const char *filename, long int decrement)
{
  int err;
  FILE *f;
  long int l;

  (*data)=NULL;
  (*data_size)=0;
  (*data_size_align)=0;

  if ((filename==NULL)||(filename[0]==0))
    return -7;

  N_DEBUGF("Opening file \"%s\"", filename)

  if (!(f=fopen(filename, "r")))
    return -1;

  N_DEBUGF("Opened %p", f)

  if (fseek(f, 0L, SEEK_END)<0) {
    err=-2;
    goto readFileAlign_exit1;
  }

  if ((l=ftell(f))<=0) {
    err=-3;
    goto readFileAlign_exit1;
  }

  N_DEBUGF("File size %lu", l)

  if (l>(((long int)FILE_BUFFER_SIZE)-decrement)) {
    err=-4;
    goto readFileAlign_exit1;
  }

  if (!((*data)=(uint8_t *)n_malloc(data_size_align, (size_t)l))) {
    err=-5;
    goto readFileAlign_exit1;
  }

  N_DEBUGF("Alloc'd data %p", *data)

  (*data_size)=(size_t)l;

  err=0;

  rewind(f);

  N_DEBUGF("Reading file %s", filename)

  if (fread((void *)(*data), sizeof(const char), (*data_size), f)==(*data_size))
    goto readFileAlign_exit1;

  N_DEBUGF("Freeing data %p", *data)

  free((void *)(*data));

  err=-6;
  (*data)=NULL;
  (*data_size)=0;
  (*data_size_align)=0;

readFileAlign_exit1:
  N_DEBUGF("Closing file %s with err = %d", filename, err)
  fclose(f);

  return err;
}

inline
int readFileAlign(uint8_t **data, size_t *data_size, size_t *data_size_align, const char *filename)
{
  return readFileAlignUtil(data, data_size, data_size_align, filename, FILE_STRUCT_SIZE);
}

inline
int readFileAlignDecrypt(uint8_t **data, size_t *data_size, size_t *data_size_align, const char *filename)
{
  return readFileAlignUtil(data, data_size, data_size_align, filename, 0);
}

void readFileAlignFree(uint8_t **data, size_t data_size)
{
#ifdef DEBUG
  int err;
#endif

  if (data) {
    memset((void *)*data, 0, data_size);
    N_DEBUGF("Cleaning *data(%p) with size = %lu with 0", *data, data_size)
    N_DEBUG_DUMP(*data, data_size)
#ifdef DEBUG
    err=gen_rand_no_entropy_util(*data, data_size);
    N_DEBUGF("Filling *data(%p) with size = %lu with random data. Err = %d", *data, data_size, err)
    N_DEBUG_DUMP(*data, data_size)
    N_DEBUGF("Freeing *data(%p)\n", *data)
#else
    gen_rand_no_entropy_util(*data, data_size);
#endif

    free((void *)*data);
    *data=NULL;
  }
}

//filename!=NULL and > 0 data NOT NULL and data_size >0
int writeFileUtil(const char *filename, uint8_t *data, size_t data_size)
{
  int err;
  FILE *f;
  if (!(f=fopen(filename, "w")))
    return -40;

  err=(fwrite((const void *)data, sizeof(const char), data_size, f)==data_size)?0:-41;

  fclose(f);
  return err;
}

uint8_t *xor_n(uint8_t *a, uint8_t *b, size_t n)
{
  do {
    n--;
    a[n]^=b[n];
  } while (n>0);

  return a;
}
//1 for valid, 0 for invalid
int check_hash512(uint8_t *h, uint8_t *data, size_t data_sz, char **errMsg)
{
  int err;
  uint8_t res[64];

  if (ssl_hash512(res, data, data_sz, errMsg))
    return 0;

  err=(memcmp(res, h, sizeof(res))==0);

  if (errMsg)
    *errMsg=(err)?"Checksum SUCCESS\n":"Wrong checksum\n";

  return err;
}

static
int get_console_passwd(char *pass, size_t pass_sz)
{
  struct termios oflags, nflags;
  int err, i;

  tcgetattr(fileno(stdin), &oflags);
  nflags=oflags;
  nflags.c_lflag&=~ECHO;
  nflags.c_lflag|=ECHONL;

  memset(pass, 0x0A, pass_sz);

  if (tcsetattr(fileno(stdin), TCSADRAIN, &nflags)) return 10;

  if (!fgets(pass, pass_sz, stdin)) {
    err=11;
    goto PASS_ERR;
  }

  err=12;

  for (i=0;i<pass_sz;i++)
    if ((pass[i])==0x0A) {
      if (i) {
        pass[i]=0;
        err=0;
      } else
        err=13;

      break;
    }

PASS_ERR:

  if (tcsetattr(fileno(stdin), TCSANOW, &oflags)) return 14;

  return err;
}

int set_password(struct pass_t **pwd)
{
  int err;

  if (!(*pwd=(struct pass_t *)malloc(sizeof(struct pass_t))))
    return -120;

  memset((void *)*pwd, 0, sizeof(struct pass_t));

  fprintf(stdout, "\nType your password: ");

  if ((err=get_console_passwd((char *)(*pwd)->passwd, (sizeof((*pwd)->passwd)-1)))) {
    N_ERRORF("Could not read console password %d\n", err)
    goto set_password_fail;
  }

  N_DEBUGF("Password typed %s", (*pwd)->passwd)

  fprintf(stdout, "\nRetype your password: ");

  if ((err=get_console_passwd((char *)(*pwd)->retype_passwd, (sizeof((*pwd)->retype_passwd)-1)))) {
    N_ERRORF("Could not read console retype password %d\n", err)
    goto set_password_fail;
  }

_Static_assert((sizeof(((struct pass_t *)0)->passwd))==(sizeof(((struct pass_t *)0)->retype_passwd)), "Sizeof retype password should be the same");

//  (*pwd)->len=strlen((*pwd)->passwd);

  N_DEBUGF("Password retyped %s", (*pwd)->retype_passwd)

  if (strcmp((void *)(*pwd)->retype_passwd, (void *)(*pwd)->passwd)) {
    err=-121;
    N_ERROR("Password does not match\n")
    goto set_password_fail;
  }

  N_DEBUG("Comparing password vectors")
  N_DEBUG_COMP_VEC((*pwd)->passwd, sizeof((*pwd)->passwd), (*pwd)->retype_passwd, sizeof((*pwd)->retype_passwd))

  return 0;

set_password_fail:

  memset((void *)(*pwd), 0, sizeof(struct pass_t));

  if (gen_rand_no_entropy_util((uint8_t *)(*pwd), sizeof(struct pass_t)))
    N_WARN("Could not reset random password")

  N_DEBUGF("Filling *pwd(%p) with size = %lu with random data. Err = %d", (*pwd), sizeof(struct pass_t), err)
  N_DEBUG_DUMP((*pwd), sizeof(struct pass_t))

  N_DEBUGF("Could not set password %d\n", err)

  free((void *)(*pwd));
  (*pwd)=NULL;

  return err;
}

int get_password(struct pass_t **pwd)
{
  int err;

  if (!(*pwd=(struct pass_t *)malloc(sizeof(struct pass_t))))
    return -130;

  memset((void *)*pwd, 0, sizeof(struct pass_t));

  fprintf(stdout, "\nType your password to unlock file: ");

  if ((err=get_console_passwd((char *)(*pwd)->passwd, (sizeof((*pwd)->passwd)-1)))) {
    N_ERRORF("Could not read console password (unlock) %d\n", err)
    goto get_password_fail;
  }

//  (*pwd)->len=strlen((*pwd)->passwd);

  N_DEBUGF("Password typed %s at %p", (*pwd)->passwd, (*pwd)->passwd)

  return 0;

get_password_fail:

  memset((void *)(*pwd), 0, sizeof(struct pass_t));

  if (gen_rand_no_entropy_util((uint8_t *)(*pwd), sizeof(struct pass_t)))
    N_WARN("Could not reset random password (unlock)")

  N_DEBUGF("Filling (unlock) *pwd(%p) with size = %lu with random data. Err = %d", (*pwd), sizeof(struct pass_t), err)
  N_DEBUG_DUMP((*pwd), sizeof(struct pass_t))

  N_DEBUGF("Could not set password (unlock) %d\n", err)

  free((void *)(*pwd));
  (*pwd)=NULL;

  return err;
}

void pass_free(struct pass_t **pwd)
{
  if (*pwd) {
    memset((void *)(*pwd), 0, sizeof(struct pass_t));

    if (gen_rand_no_entropy_util((uint8_t *)(*pwd), sizeof(struct pass_t)))
      N_WARN("Could not reset random password at free")

    N_DEBUGF("Filling *pwd(%p) with size = %lu with random data.", (*pwd), sizeof(struct pass_t))
    N_DEBUG_DUMP((*pwd), sizeof(struct pass_t))

    free((void *)(*pwd));
    (*pwd)=NULL;
  }
}

inline
char *get_version_str()
{
  static char str[16];
  snprintf(str, sizeof(str), "%d.%d.%d", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);

  return str;
}

