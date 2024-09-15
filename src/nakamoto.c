#include <nakamoto.h>
#include <rnd.h>
#include <string.h>
#include <stdlib.h>
#include <logger.h>

#define FILE_BUFFER_BLOCK (size_t)2*FILE_BUFFER_SIZE
#define FILE_DESCRIPTION "Nakamoto encrypted file"
#define ARGON2ID_MEM_COST (uint32_t)(32*32*1024)
#define ARGON2ID_INTERACTION_COST (uint32_t)(3+60)
#define ARGON2ID_PARALLEL_COST (uint32_t)(4+80)
#define OUT_FILENAME "out.txt"
#define OUT_FILENAME_ENCRYPTED "out.nkm"

#ifdef VISIBLE_FOR_TEST
inline uint32_t getArgon2idMemCost() {
  return ARGON2ID_MEM_COST;
}

inline uint32_t getArgon2idInteractionCost() {
  return ARGON2ID_INTERACTION_COST;
}

inline uint32_t getArgon2idParallelCost() {
  return ARGON2ID_PARALLEL_COST;
}
#endif

_Static_assert(sizeof(((struct file_struct_t *)0)->description)>=sizeof(FILE_DESCRIPTION), "Description exceed size");

struct file_util_t *WRITE_begin_header(uint64_t timeout) {
  int err;
  uint8_t
    *_file_buffer; // encrypted data by key ; + encrypted data by key 1 = FILE_BUFFER_BLOCK = 2*FILE_BUFFER_SIZE
  char *msg;
  struct file_struct_t *file_struct;
  struct file_util_t *file_util;
#ifdef DEBUG
  struct cipher_block_t *cipher_block;
  struct cipher_block_data_t *cipher_block_data;
#endif

  N_DEBUGF("WRITE_begin_header with timeout: %lu", timeout)

  if (!(file_struct=(struct file_struct_t *)malloc(FILE_STRUCT_SIZE)))
    return NULL;

  N_DEBUGF("WRITE_begin_header alloc'd size %lu bytes at %p", FILE_STRUCT_SIZE, file_struct)

  N_DEBUG("verify_system_entropy. Verify entropy")

  if (verify_system_entropy(F_ENTROPY_TYPE_PARANOIC, (uint8_t *)file_struct, FILE_STRUCT_SIZE, timeout))
    goto WRITE_begin_header_exit1;

  N_DEBUGF("Check iv1 %p of size %lu", file_struct->iv1, sizeof(file_struct->iv1))

  N_DEBUG_DUMP(file_struct->iv1, sizeof(file_struct->iv1))

  N_DEBUGF("Check salt1 %p of size %lu", file_struct->salt1, sizeof(file_struct->salt1))

  N_DEBUG_DUMP(file_struct->salt1, sizeof(file_struct->salt1))

  N_DEBUG("verify_system_entropy: Success")

  N_DEBUGF("_file_buffer: Alloc size %lu bytes", FILE_BUFFER_BLOCK)

  if (!(_file_buffer=(uint8_t *)malloc(FILE_BUFFER_BLOCK)))
    goto WRITE_begin_header_exit1;

  N_DEBUGF("_file_buffer: Alloc'd size %lu bytes at %p success", FILE_BUFFER_BLOCK, _file_buffer)

  N_DEBUGF("file_util: Alloc size %lu bytes", sizeof(struct file_util_t))

  if ((file_util=(struct file_util_t *)malloc(sizeof(struct file_util_t)))) {

    N_DEBUGF("file_util: Alloc size %lu bytes %p success", sizeof(struct file_util_t), file_util)

    file_util->file_struct=file_struct;
    file_util->_file_buffer=_file_buffer;

    N_DEBUG("file_util->magic: set magic")

    memcpy(file_struct->magic, NAKAMOTO, CONST_STR_LEN(NAKAMOTO));

    file_struct->version=setU32_LE(NAKAMOTO_VERSION_SET);
//    file_struct->iteraction=setU32_LE(INTERATION);

    N_DEBUGF("Version: %d", NAKAMOTO_VERSION_SET)
    N_DEBUGF("Interaction: %d", INTERACTION)

    N_DEBUG("file_util->description:" FILE_DESCRIPTION)
    memcpy(file_struct->description, FILE_DESCRIPTION, sizeof(FILE_DESCRIPTION));

//#define FILE_STRUCT_DATA_HASH_SZ sizeof(*file_struct)-sizeof(file_struct->sha512)
    if ((err=ssl_hash512(file_struct->sha512, (uint8_t *)file_struct, FILE_STRUCT_DATA_HASH_SZ, &msg))) {
      N_ERRORF("ssl_hash512 error with err = %d with message: %s", err, msg)
      goto WRITE_begin_header_exit2;
    }

    N_DEBUGF("Hash 512 success with message \"%s\" with data size %lu\nWith DUMP:", msg, FILE_STRUCT_DATA_HASH_SZ)

    N_DEBUG_DUMP_A(file_struct, FILE_STRUCT_DATA_HASH_SZ)

    N_DEBUG("With HASH:")

    N_DEBUG_DUMP(file_struct->sha512, sizeof(file_struct->sha512))

//#undef FILE_STRUCT_DATA_HASH_SZ
#ifdef DEBUG
    cipher_block=(struct cipher_block_t *)&file_struct[1];

    N_DEBUGF("Setup cipher_block %p with size %lu", cipher_block, sizeof(struct cipher_block_t))
#endif
//    cipher_block->memory_cost=setU32_LE(ARGON2ID_MEM_COST);
//    N_DEBUGF("Setup memory cost in Argon2id %u", ARGON2ID_MEM_COST)

//    cipher_block->interaction_cost=setU32_LE(ARGON2ID_INTERACTION_COST);
//    N_DEBUGF("Setup interaction cost in Argon2id %u", cipher_block->interaction_cost)

//    cipher_block->parallel_cost=setU32_LE(ARGON2ID_PARALLEL_COST);
//    N_DEBUGF("Setup parallel cost in Argon2id %u", cipher_block->parallel_cost)

    N_DEBUGF("Check additional %p of size %lu", cipher_block->additional, sizeof(cipher_block->additional))

    N_DEBUG_DUMP(cipher_block->additional, sizeof(cipher_block->additional))

    N_DEBUGF("Check secret %p of size %lu", cipher_block->secret, sizeof(cipher_block->secret))

    N_DEBUG_DUMP(cipher_block->secret, sizeof(cipher_block->secret))

    N_DEBUGF("Check iv2 %p of size %lu", cipher_block->iv2, sizeof(cipher_block->iv2))

    N_DEBUG_DUMP(cipher_block->iv2, sizeof(cipher_block->iv2))

#ifdef DEBUG
    cipher_block_data=(struct cipher_block_data_t *)&cipher_block[1];
    N_DEBUGF("Check hash_xored_restore %p of size %lu", cipher_block_data->hash_xored_restore, sizeof(cipher_block_data->hash_xored_restore))

    N_DEBUG_DUMP(cipher_block_data->hash_xored_restore, sizeof(cipher_block_data->hash_xored_restore))
#endif

    return file_util;

WRITE_begin_header_exit2:
    free((void *)file_util);

  }

  free((void *)_file_buffer);

WRITE_begin_header_exit1:
  free((void *)file_struct);

  return NULL;
}

void WRITE_end_header(struct file_util_t **file_util)
{
  uint8_t *_file_buffer;
  struct file_struct_t *file_struct;

  if (*file_util) {

    N_DEBUGF("WRITE_end_header: Begin free %p", *file_util)

    file_struct=(*file_util)->file_struct;
    _file_buffer=(*file_util)->_file_buffer;

    N_DEBUGF("WRITE_end_header: Cleaning *file_util(%p) of size %lu", *file_util, sizeof(struct file_util_t))
    memset((*file_util), 0, sizeof(struct file_util_t));
    N_DEBUG_DUMP((*file_util), sizeof(struct file_util_t))

    N_DEBUGF("WRITE_end_header: Cleaning _file_buffer(%p) of size %lu", _file_buffer, FILE_BUFFER_BLOCK)
    memset(_file_buffer, 0, FILE_BUFFER_BLOCK);
    //N_DEBUG_DUMP(_file_buffer, FILE_BUFFER_BLOCK)

    N_DEBUGF("WRITE_end_header: Cleaning file_struct(%p) of size %lu", file_struct, FILE_STRUCT_SIZE)
    memset(file_struct, 0, FILE_STRUCT_SIZE);
    N_DEBUG_DUMP(file_struct, FILE_STRUCT_SIZE)

    if (gen_rand_no_entropy_util((uint8_t *)(*file_util), sizeof(struct file_util_t)))
      N_WARN("reset file_util struct")
    N_DEBUGF("WRITE_end_header: Randomize *file_util(%p) of size %lu", *file_util, sizeof(struct file_util_t))
    N_DEBUG_DUMP(*file_util, sizeof(struct file_util_t))

    if (gen_rand_no_entropy_util((uint8_t *)_file_buffer, FILE_BUFFER_BLOCK))
      N_WARN("reset _file_buffer struct\n");
    N_DEBUGF("WRITE_end_header: Randomize _file_buffer(%p) of size %lu", _file_buffer, FILE_BUFFER_BLOCK)

    if (gen_rand_no_entropy_util((uint8_t *)file_struct, FILE_STRUCT_SIZE))
      N_WARN("reset file_struct struct\n");
    N_DEBUGF("WRITE_end_header: Randomize file_struct(%p) of size %lu", file_struct, FILE_STRUCT_SIZE)
    N_DEBUG_DUMP(file_struct, FILE_STRUCT_SIZE)

    N_DEBUGF("WRITE_end_header: Freeing *file_util(%p)", (*file_util))
    free((void *)(*file_util));

    N_DEBUGF("WRITE_end_header: Freeing _file_buffer(%p)", _file_buffer)
    free((void *)_file_buffer);

    N_DEBUGF("WRITE_end_header: Freeing file_struct(%p)", file_struct)
    free((void *)file_struct);

    *file_util=NULL;
  }
}

// return 0 if sucess
// !!! Assumes always: n > max >= min
#ifndef VISIBLE_FOR_TEST
static
#endif
int pass_must_have_at_least(size_t *passwd_sz, char *password, size_t n, size_t min, size_t max, int must_have)
{
  int err;
  size_t i;
  char c;

  *passwd_sz=0;

  if (!password)
    return PASS_IS_NULL;

  if (((*passwd_sz)=strnlen(password, n))==n)
    return PASS_IS_OUT_OVF;

  if (min>(*passwd_sz))
    return PASS_IS_TOO_SHORT;

  if ((*passwd_sz)>max)
    return PASS_IS_TOO_LONG;

  if ((err=PASS_MUST_HAVE_AT_LEAST_NONE)==must_have)
    return err;

  for (i=0;i<(*passwd_sz);i++) {
    if (err==must_have)
      break;

    c=password[i];

    if (must_have&PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)
      if ((err&PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)==0) {
        if (c>'z')
          goto pass_must_have_at_least_STEP0;

        if (c<'a')
          goto pass_must_have_at_least_STEP0;

        err|=PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE;

        continue;
       }

pass_must_have_at_least_STEP0:

  if (must_have&PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER)
    if ((err&PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER)==0) {
      if (c>'9')
        goto pass_must_have_at_least_STEP1;

      if (c<'0')
        goto pass_must_have_at_least_STEP1;

      err|=PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER;

      continue;
  }

pass_must_have_at_least_STEP1:

  if (must_have&PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)
    if ((err&PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)==0) {

      if (c>'Z')
        goto pass_must_have_at_least_STEP2;

      if (c<'A')
        goto pass_must_have_at_least_STEP2;

      err|=PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE;

      continue;
  }

pass_must_have_at_least_STEP2:

  if (must_have&PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL)
    if ((err&PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL)==0) {
      if (c==0x7F)
        continue;

      if (c<'!')
        continue;

      if (c>'z')
        goto pass_must_have_at_least_EXIT1;

      if (c>'`')
        continue;

      if (c>'Z')
        goto pass_must_have_at_least_EXIT1;

      if (c>'@')
        continue;

      if (c>'9')
        goto pass_must_have_at_least_EXIT1;

      if (c>'/')
        continue;

pass_must_have_at_least_EXIT1:
      err|=PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL;
    }

  }

  return (err^must_have);
}

int WRITE_derive_keys(struct file_util_t *file_util, const char *password, const char *filename)
{
  int err;
  char *errMsg;
  size_t password_len;
  uint8_t *data, *p, *q;
  size_t data_size, data_size_align, size_tmp;
  struct cipher_block_t *cipher_block;
  struct cipher_block_data_t *cipher_block_data;

  if ((err=pass_must_have_at_least(&password_len, (char *)password, N_MAX, MIN_PASSWD, MAX_PASSWD, MUST_HAVE))) {
    if (err&PASS_IS_NULL)
      errMsg="Password is NULL\n";
    else if (err&PASS_IS_OUT_OVF)
      errMsg="Password buffer overflow\n";
    else if (err&PASS_IS_TOO_SHORT)
      errMsg="Password is too short\n";
    else if (err&PASS_IS_TOO_LONG)
      errMsg="Password is too long\n";
    else
      errMsg="Password must have:\n\tMin. size: 16\n\tMax. size: 64\n\tAt least one symbol\n\tAt least one upper case\n\t\
At least one number\n\tAt least one lower case\n\t";
    N_ERRORF("Err.: %d\n%s", err, errMsg)

    return err;
  }

  N_DEBUGF("Password pass %s with size %lu", password, password_len)

  N_DEBUGF("Begin PBKDF2 with iteration %u", INTERACTION)

  if ((err=pbkdf2(
    file_util->priv_key1, sizeof(file_util->priv_key1),
    (const char *)password, (int)password_len,
    file_util->file_struct->salt1, sizeof(file_util->file_struct->salt1),
    INTERACTION,
    &errMsg
  ))) {
    N_ERRORF("Error PBKDF2 %d with message %s\n", err, errMsg)
    return err;
  }

  N_DEBUGF("End PBKDF2 with out %p of size %lu with err = %d and message %s", file_util->priv_key1, sizeof(file_util->priv_key1), err, errMsg);
  N_DEBUG_DUMP(file_util->priv_key1, sizeof(file_util->priv_key1))

  if ((err=readFileAlign(&data, &data_size, &data_size_align, filename))) {
    N_ERRORF("Could not open filename %s. Error: %d\n", filename, err)
    return err;
  }

  N_DEBUGF("Read file %s with size %lu, aligned %lu with pointer %p", filename, data_size, data_size_align, data)
  N_DEBUG_DUMP_A(data, data_size_align)

  cipher_block=(struct cipher_block_t *)&file_util->file_struct[1];

  N_DEBUGF("BEFORE: Cipher block %p with salt2 = %p of size %lu", cipher_block, cipher_block->hash_xored, sizeof(cipher_block->hash_xored))
  N_DEBUG_DUMP(cipher_block->hash_xored, sizeof(cipher_block->hash_xored))

  if ((err=ssl_hash512(cipher_block->hash_xored, data, data_size, &errMsg))) {
    N_ERRORF("SHA 512 error with message: \"%s\" with err %d\n", errMsg, err)
    goto WRITE_derive_keys_exit1;
  }

  N_DEBUGF("AFTER (SHA512 step 1): Cipher block %p with salt2 = %p of size %lu", cipher_block, cipher_block->hash_xored, sizeof(cipher_block->hash_xored))
  N_DEBUG_DUMP(cipher_block->hash_xored, sizeof(cipher_block->hash_xored))

  cipher_block_data=(struct cipher_block_data_t *)&cipher_block[1];

  cipher_block_data->file_size=setU64_LE(data_size);

  N_DEBUGF("Data size (file): %lu", cipher_block_data->file_size)
  N_DEBUG_DUMP(&cipher_block_data->file_size, sizeof(cipher_block_data->file_size))

  N_DEBUGF(
    "Cipher block data %p with hash_xored_restore = %p of size %lu",
    cipher_block_data,
    cipher_block_data->hash_xored_restore,
    sizeof(cipher_block_data->hash_xored_restore)
  )
  N_DEBUG_DUMP(cipher_block_data->hash_xored_restore, sizeof(cipher_block_data->hash_xored_restore))

_Static_assert(sizeof(cipher_block->hash_xored)==sizeof(cipher_block_data->hash_xored_restore), "Refactor XOR vector size");
  xor_n(cipher_block->hash_xored, cipher_block_data->hash_xored_restore, sizeof(cipher_block->hash_xored));

  N_DEBUGF("AFTER (SHA512 step 2): Cipher block %p with salt2 = %p of size %lu", cipher_block, cipher_block->hash_xored, sizeof(cipher_block->hash_xored))
  N_DEBUG_DUMP(cipher_block->hash_xored, sizeof(cipher_block->hash_xored))

  N_DEBUGF(
    "\n\tMem. cost: %u\n\tIter. count: %u\n\tParallel cost: %u\n",
    ARGON2ID_MEM_COST,
    ARGON2ID_INTERACTION_COST,
    ARGON2ID_PARALLEL_COST
  )

  if ((err=argon2id(
    file_util->priv_key2, sizeof(file_util->priv_key2),
    (const char *)password, (int)password_len,
    cipher_block->hash_xored, sizeof(cipher_block->hash_xored),
    cipher_block->additional, sizeof(cipher_block->additional),
    cipher_block->secret, sizeof(cipher_block->secret),
    ARGON2ID_MEM_COST,
    ARGON2ID_INTERACTION_COST,
    ARGON2ID_PARALLEL_COST,
    &errMsg
  ))) {
    N_ERRORF("Error Argon2id %d with message %s\n", err, errMsg)
    goto WRITE_derive_keys_exit1;
  }

  N_DEBUGF("End Argon2id with out %p of size %lu with err = %d and message %s", file_util->priv_key2, sizeof(file_util->priv_key2), err, errMsg);
  N_DEBUG_DUMP(file_util->priv_key2, sizeof(file_util->priv_key2))

  N_DEBUGF(
    "Copy file struct from file_util->file_struct %p to file_util->_file_buffer %p of size %lu",
    file_util->file_struct, file_util->_file_buffer, FILE_STRUCT_SIZE
  )
  memcpy((void *)file_util->_file_buffer, (void *)file_util->file_struct, FILE_STRUCT_SIZE);
  N_DEBUG_COMP_VEC(file_util->_file_buffer, FILE_STRUCT_SIZE, file_util->file_struct, FILE_STRUCT_SIZE)

  p=&file_util->_file_buffer[FILE_STRUCT_SIZE];

  N_DEBUGF("Copy data file from data %p to &file_util->_file_buffer[FILE_STRUCT_SIZE] %p of size %lu", data, p, data_size_align)

  memcpy((void *)p, (void *)data, data_size_align);
  N_DEBUG_DUMP_A(file_util->_file_buffer, FILE_STRUCT_SIZE+data_size_align)

  N_DEBUG("Begin encrypt (layer 2) with private key 2");

  //p=(uint8_t *)&((struct cipher_block_t *)(&((struct file_struct_t *)file_util->_file_buffer)[1]))[1];
  p=&file_util->_file_buffer[FILE_STRUCT_SIZE-sizeof(struct cipher_block_data_t)];
  size_tmp=FILE_BUFFER_SIZE;

  q=&file_util->_file_buffer[FILE_BUFFER_SIZE];

  if ((err=aes_256_cbc_encrypt(
    q, &size_tmp,
    p, sizeof(struct cipher_block_data_t)+data_size_align,
    cipher_block->iv2, file_util->priv_key2,
    &errMsg
  ))) {
    N_ERRORF("aes_256_cbc_encrypt(key 2) error with message \"%s\" with err %d", errMsg, err)
    goto WRITE_derive_keys_exit1;
  }

#ifdef DEBUG
  if (size_tmp==(sizeof(struct cipher_block_data_t)+data_size_align))
    N_INFO("Pass size_tmp")
  else {
    N_ERRORF("size_tmp = %lu differs from correct size %lu", size_tmp, sizeof(struct cipher_block_data_t)+data_size_align)
    goto WRITE_derive_keys_exit1;
  }
#endif

  N_DEBUGF("Block encrypted at %p (key 2) with private key 2 %p", q, file_util->priv_key2)
  N_DEBUGF("Private KEY 2 %p", file_util->priv_key2)
  N_DEBUG_DUMP(file_util->priv_key2, sizeof(file_util->priv_key2))
  N_DEBUGF("IV 2 %p", cipher_block->iv2)
  N_DEBUG_DUMP(cipher_block->iv2, sizeof(cipher_block->iv2))

  N_DEBUGF("\nEncrypted data 1 %p of size %lu", q, size_tmp)
  N_DEBUG_DUMP(q, size_tmp)

  N_DEBUGF("Copy back 1 from q(%p) to p(%p) of size %lu", q, p, size_tmp)
  memcpy((void *)p, (void *)q, size_tmp);
  N_DEBUG_COMP_VEC(p, size_tmp, q, size_tmp)

  size_tmp=FILE_BUFFER_SIZE;

  p=&file_util->_file_buffer[FILE_STRUCT_SIZE-(sizeof(struct cipher_block_t) + sizeof(struct cipher_block_data_t))];

  N_DEBUG("Begin encrypt (layer 1) with private key 1");
  N_DEBUGF("Private KEY 1 %p", file_util->priv_key1)
  N_DEBUG_DUMP(file_util->priv_key1, sizeof(file_util->priv_key1))
  N_DEBUGF("IV 1 %p", file_util->file_struct->iv1)
  N_DEBUG_DUMP(file_util->file_struct->iv1, sizeof(file_util->file_struct->iv1))

  if ((err=aes_256_cbc_encrypt(
    q, &size_tmp,
    p, sizeof(struct cipher_block_t) + sizeof(struct cipher_block_data_t) + data_size_align,
    file_util->file_struct->iv1, file_util->priv_key1,
    &errMsg
  ))) {
    N_ERRORF("aes_256_cbc_encrypt(key 1) error with message \"%s\" with err %d", errMsg, err)
    goto WRITE_derive_keys_exit1;
  }

#ifdef DEBUG
  if (size_tmp==(sizeof(struct cipher_block_t) + sizeof(struct cipher_block_data_t) + data_size_align))
    N_INFO("Pass size_tmp")
  else {
    N_ERRORF("size_tmp = %lu differs from correct size %lu", size_tmp, sizeof(struct cipher_block_t) + sizeof(struct cipher_block_data_t) + data_size_align)
    goto WRITE_derive_keys_exit1;
  }
#endif

  N_DEBUGF("\nEncrypted data 2 %p of size %lu", q, size_tmp)
  N_DEBUG_DUMP(q, size_tmp)

  N_DEBUGF("Copy back 2 from q(%p) to p(%p) of size %lu", q, p, size_tmp)
  memcpy((void *)p, (void *)q, size_tmp);
  N_DEBUG_COMP_VEC(p, size_tmp, q, size_tmp)

  if ((err=writeFileUtil(OUT_FILENAME_ENCRYPTED, file_util->_file_buffer, sizeof(struct file_struct_t) + size_tmp)))
    N_ERRORF("Could not write to file %d", err)

WRITE_derive_keys_exit1:
  readFileAlignFree(&data, data_size_align);

  return err;
}

struct file_util_t *READ_begin_header()
{
  struct file_util_t *file_util=(struct file_util_t *)malloc(sizeof(struct file_util_t));

  if (file_util)
    if (!(file_util->_file_buffer=(uint8_t *)malloc(FILE_BUFFER_BLOCK))) {
      free((void *)file_util);
      file_util=NULL;
    }

  N_DEBUGF("READ begin header %p", file_util)

  return file_util;
}

int READ_extract(struct file_util_t *file_util, const char *password, const char *filename)
{
  int err;
  uint8_t *data, *p;
  uint32_t u32;
  size_t
    data_size,
    data_size_align;
  char *msg;
  struct cipher_block_t *cipher_block;
  struct cipher_block_data_t *cipher_block_data;

  if ((err=readFileAlignDecrypt(&data, &data_size, &data_size_align, filename))) {
    N_ERRORF("Could not open file %s. Error %d", filename, err)
    return err;
  }

  N_DEBUGF("READ. File %s opened %p with size %lu aligned %lu", filename, data, data_size, data_size_align)
  N_DEBUG_DUMP_A(data, data_size_align)

  if (data_size_align!=data_size) {
    N_ERRORF("Not aligned data size: %lu data size align %lu", data_size, data_size_align)
    err=80;
    goto READ_extract_exit1;
  }

  if (FILE_STRUCT_SIZE>=data_size_align) {
    N_ERRORF("Wrong file structure in %s", filename)
    err=81;
    goto READ_extract_exit1;  
  }

  if (memcmp((file_util->file_struct=(struct file_struct_t *)data)->magic, NAKAMOTO, CONST_STR_LEN(NAKAMOTO))) {
    N_ERRORF("Wrong magic in %s", filename)
    err=82;
    goto READ_extract_exit1;
  }

  u32=setU32_LE(file_util->file_struct->version);

  N_DEBUGF("Check version in %s\n\tVersion: %d.%d.%d", filename, GET_VER_MAJ(u32), GET_VER_MIN(u32), GET_VER_REV(u32))

  if ((err=((GET_VER_MAJ(u32)!=VERSION_MAJOR)||(GET_VER_MIN(u32)!=VERSION_MINOR)))) {
    err=83;
    N_ERRORF(
      "Unexpected version in %s. Expected %d.%d. But found %d.%d",
      filename,
      VERSION_MAJOR, VERSION_MINOR,
      GET_VER_MAJ(u32), GET_VER_MIN(u32)
    )
    goto READ_extract_exit1;
  }

  if (!check_hash512(file_util->file_struct->sha512, (uint8_t *)file_util->file_struct, FILE_STRUCT_DATA_HASH_SZ, &msg)) {
    err=84;
    N_ERRORF("Wrong checksum in %s with message %s", filename, msg)
    goto READ_extract_exit1;
  }

  N_DEBUGF("Checksum in filename %s pass with message %s", filename, msg)

  N_DEBUG("Extracting private key")

  if ((err=pbkdf2(
    file_util->priv_key1, sizeof(file_util->priv_key1),
    password, -1,
    file_util->file_struct->salt1, sizeof(file_util->file_struct->salt1),
    INTERACTION,
    &msg
  ))) {
    N_ERRORF("Error extracting private key 1. %s. Err.: %d", msg, err)
    goto READ_extract_exit1;
  }

  N_DEBUGF("Extracted private key 1 at %p with size %lu", file_util->priv_key1, sizeof(file_util->priv_key1))
  N_DEBUG_DUMP(file_util->priv_key1, sizeof(file_util->priv_key1))

  p=(uint8_t *)&file_util->file_struct[1];

  N_DEBUGF("Begin decrypt data (1st step) from %p to %p of size %lu", p, file_util->_file_buffer, data_size_align-sizeof(struct file_struct_t))

  data_size=FILE_BUFFER_SIZE;
  if ((err=aes_256_cbc_decrypt(
    file_util->_file_buffer, &data_size,
    p, data_size_align-sizeof(struct file_struct_t),
    file_util->file_struct->iv1, file_util->priv_key1,
    &msg
  ))) {
    N_ERRORF("Error decrypt data %s. Err %d", msg, err)
    goto READ_extract_exit1;
  }

  N_DEBUGF("Cleaning private key 1 (BEFORE) at %p with size %lu", file_util->priv_key1, sizeof(file_util->priv_key1))
  N_DEBUG_DUMP(file_util->priv_key1, sizeof(file_util->priv_key1))
  memset(file_util->priv_key1, 0, sizeof(file_util->priv_key1));
  N_DEBUGF("Cleaning private key 1 (AFTER) at %p with size %lu", file_util->priv_key1, sizeof(file_util->priv_key1))
  N_DEBUG_DUMP(file_util->priv_key1, sizeof(file_util->priv_key1))

  if ((data_size_align-data_size)!=sizeof(struct file_struct_t)) {
    err=85;
    N_ERROR("Decryption error. Fatal. 85")
    goto READ_extract_exit1;
  }

  cipher_block=(struct cipher_block_t *)file_util->_file_buffer;

  N_DEBUGF("Begin extract private key2 %p with size %lu", file_util->priv_key2, sizeof(file_util->priv_key2))

  if ((err=argon2id(
    file_util->priv_key2, sizeof(file_util->priv_key2),
    password, -1,
    cipher_block->hash_xored, sizeof(cipher_block->hash_xored),
    cipher_block->additional, sizeof(cipher_block->additional),
    cipher_block->secret, sizeof(cipher_block->secret),
    ARGON2ID_MEM_COST,
    ARGON2ID_INTERACTION_COST,
    ARGON2ID_PARALLEL_COST,
    &msg
  ))) {
    N_ERRORF("Error extracting private key 2. %s. Err.: %d", msg, err)
    goto READ_extract_exit1;
  }

  N_DEBUGF("Extracted private key 2 at %p with size %lu", file_util->priv_key2, sizeof(file_util->priv_key2))
  N_DEBUG_DUMP(file_util->priv_key2, sizeof(file_util->priv_key2))

  p=(uint8_t *)&cipher_block[1];

  N_DEBUGF("Begin decrypt data (2st step) from %p to %p of size %lu", p, &file_util->_file_buffer[FILE_BUFFER_SIZE],
    data_size_align-sizeof(struct file_struct_t)-sizeof(struct cipher_block_t))

  cipher_block_data=(struct cipher_block_data_t *)&file_util->_file_buffer[FILE_BUFFER_SIZE];
  data_size=FILE_BUFFER_SIZE;
  if ((err=aes_256_cbc_decrypt(
    (uint8_t *)cipher_block_data, &data_size,
    p, data_size_align-sizeof(struct file_struct_t)-sizeof(struct cipher_block_t),
    cipher_block->iv2, file_util->priv_key2,
    &msg
  ))) {
    N_ERRORF("Error decrypt data(2) %s. Err %d", msg, err)
    goto READ_extract_exit1;
  }

  N_DEBUGF("Cleaning private key 2 (BEFORE) at %p with size %lu", file_util->priv_key2, sizeof(file_util->priv_key2))
  N_DEBUG_DUMP(file_util->priv_key2, sizeof(file_util->priv_key2))
  memset(file_util->priv_key2, 0, sizeof(file_util->priv_key2));
  N_DEBUGF("Cleaning private key 2 (AFTER) at %p with size %lu", file_util->priv_key2, sizeof(file_util->priv_key2))
  N_DEBUG_DUMP(file_util->priv_key2, sizeof(file_util->priv_key2))

  if ((data_size_align-data_size)!=(sizeof(struct file_struct_t)+sizeof(struct cipher_block_t))) {
    err=86;
    N_ERROR("Decryption error. Fatal. 86")
    goto READ_extract_exit1;
  }

  data_size=data_size_align-FILE_STRUCT_SIZE;
  N_DEBUGF("\n\tData size (align): %lu\n\tFile struct Size %lu\n\tData size %lu\n", data_size_align, FILE_STRUCT_SIZE, data_size)
  if ((cipher_block_data->file_size>(uint64_t)data_size)||(cipher_block_data->file_size==0))
    N_WARNF("Wrong block file size %lu realign to %lu. Maybe wrong password of file corrupted", cipher_block_data->file_size, data_size)
  else
    data_size=(size_t)cipher_block_data->file_size;

  p=(uint8_t *)&cipher_block_data[1];

  N_DEBUGF("Revert checksum (BEFORE) at %p with size %lu", cipher_block->hash_xored, sizeof(cipher_block->hash_xored))
  N_DEBUG_DUMP(cipher_block->hash_xored, sizeof(cipher_block->hash_xored))

  xor_n(cipher_block->hash_xored, cipher_block_data->hash_xored_restore, sizeof(cipher_block->hash_xored));

  N_DEBUGF("Revert checksum (AFTER) at %p with size %lu", cipher_block->hash_xored, sizeof(cipher_block->hash_xored))
  N_DEBUG_DUMP(cipher_block->hash_xored, sizeof(cipher_block->hash_xored))

  if (!check_hash512(cipher_block->hash_xored, p, data_size, &msg)) {
    err=87;
    N_ERRORF("Wrong password or corrupted file with: %s ", msg)
    goto READ_extract_exit1;
  }

  if ((err=writeToFile(OUT_FILENAME, p, data_size)))
    N_ERRORF("Write to file error %d. Could not write \""OUT_FILENAME"\"\n", err)
  else
    N_INFO("Success. \""OUT_FILENAME"\"\n")

READ_extract_exit1:
  readFileAlignFree(&data, data_size_align);

  return err;
}

void READ_end_header(struct file_util_t **file_util)
{
  uint8_t *_file_buffer;

  if (*file_util) {

    _file_buffer=(*file_util)->_file_buffer;

    N_DEBUGF("READ_end_header: Begin free %p", *file_util)

    N_DEBUGF("READ_end_header: Cleaning *file_util(%p) of size %lu", *file_util, sizeof(struct file_util_t))
    memset((*file_util), 0, sizeof(struct file_util_t));
    N_DEBUG_DUMP((*file_util), sizeof(struct file_util_t))

    N_DEBUGF("READ_end_header: Cleaning _file_buffer(%p) of size %lu", _file_buffer, FILE_BUFFER_BLOCK)
    memset(_file_buffer, 0, FILE_BUFFER_BLOCK);

    if (gen_rand_no_entropy_util((uint8_t *)(*file_util), sizeof(struct file_util_t)))
      N_WARN("READ reset file_util struct")
    N_DEBUGF("READ_end_header: Randomize *file_util(%p) of size %lu", *file_util, sizeof(struct file_util_t))
    N_DEBUG_DUMP(*file_util, sizeof(struct file_util_t))

    if (gen_rand_no_entropy_util((uint8_t *)_file_buffer, FILE_BUFFER_BLOCK))
      N_WARN("READ reset _file_buffer struct\n");
    N_DEBUGF("READ_end_header: Randomize _file_buffer(%p) of size %lu", _file_buffer, FILE_BUFFER_BLOCK)

    N_DEBUGF("READ_end_header: Freeing *file_util(%p)", (*file_util))
    free((void *)(*file_util));

    N_DEBUGF("READ_end_header: Freeing _file_buffer(%p)", _file_buffer)
    free((void *)_file_buffer);

    *file_util=NULL;
  }
}

