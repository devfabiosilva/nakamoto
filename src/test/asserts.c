//Fri abr 02 20:42:11 -03 2021
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <asserts.h>
#include <time.h>
#include <math.h>

static int c_test_not_ignored=C_TEST_TRUE;

static void print_assert_int(void *, void *);
static void print_assert_longint(void *, void *);
static void print_assert_unsigned_longint(void *, void *);
static void print_assert_byte(void *, void *);
static void print_assert_double(void *, void *);
static void print_assert_string(void *, void *);
static void print_assert_nullable(void *, void *);
static void print_assert_u8(void *, void *);
static void print_assert_s8(void *, void *);
static void print_assert_u16(void *, void *);
static void print_assert_s16(void *, void *);
static void print_assert_u32(void *, void *);
static void print_assert_s32(void *, void *);
static void print_assert_u64(void *, void *);
static void print_assert_s64(void *, void *);
static void print_assert_fail(void *, void *);
static int free_vargs(void *);

static void abort_tests();

/*
static void debug_hex_dump(unsigned char *data, size_t data_size)
{
   if (!data) {
      printf("\nWARNING: NULL pointer. Aborting\n");
      return;
   }
   if (!data_size)
      return;

   for (;data_size--;)
      printf("%02X ", (unsigned char)*(data++));
}
*/

_Static_assert(C_TEST_TRUE==1, "Compiler should return 1 for TRUE");
_Static_assert(C_TEST_FALSE==0, "Compiler should return 0 for FALSE");

#define C_TEST_HEADER_SIGNATURE (uint32_t)(0x0012E4992)

void *_c_test_ptr=NULL;

typedef void (*header_on_cb)(void *);

typedef struct c_test_header {
   uint32_t signature;

   size_t
   tests,
   next,
   ignored;

   uint64_t
   initial_timestamp,
   final_timestamp;

   header_on_cb
   on_add_test_fn,
   on_test_fn,
   on_begin_test_fn,
   on_end_test_fn,
   on_abort_fn;

} C_TEST_HEADER;

typedef struct c_test_fn_description {
   uint32_t type;
   const char *fn_name;
   size_t blk_size;
   void (*cb)(void *, void *);
} C_TEST_FN_DESCRIPTION;

typedef C_TEST_FN_DESCRIPTION C_TEST_FN_META;

typedef struct c_test_type_header_t {
   C_TEST_FN_DESCRIPTION desc;
} C_TEST_TYPE_HEADER;

typedef struct c_test_type_u8_t {
   C_TEST_TYPE_HEADER header;

   uint8_t
   expected,
   result;
} C_TEST_TYPE_U8;

typedef struct c_test_type_s8_t {
   C_TEST_TYPE_HEADER header;

   int8_t
   expected,
   result;
} C_TEST_TYPE_S8;

typedef struct c_test_type_u16_t {
   C_TEST_TYPE_HEADER header;

   uint16_t
   expected,
   result;
} C_TEST_TYPE_U16;

typedef struct c_test_type_s16_t {
   C_TEST_TYPE_HEADER header;

   int16_t
   expected,
   result;
} C_TEST_TYPE_S16;

typedef struct c_test_type_int_t {
   C_TEST_TYPE_HEADER header;

   int
   expected,
   result;
} C_TEST_TYPE_INT, C_TEST_TYPE_BOOL;

typedef struct c_test_type_u32_t {
   C_TEST_TYPE_HEADER header;

   uint32_t
   expected,
   result;
} C_TEST_TYPE_U32;

typedef struct c_test_type_s32_t {
   C_TEST_TYPE_HEADER header;

   int32_t
   expected,
   result;
} C_TEST_TYPE_S32;


typedef struct c_test_type_long_int_t {
   C_TEST_TYPE_HEADER header;

   long long int
   expected,
   result;
} C_TEST_TYPE_LONG_INT;

typedef struct c_test_type_unsigned_long_int_t {
   C_TEST_TYPE_HEADER header;

   unsigned long long int
   expected,
   result;
} C_TEST_TYPE_UNSIGNED_LONG_INT;

typedef struct c_test_type_s64_t {
   C_TEST_TYPE_HEADER header;

   int64_t
   expected,
   result;
} C_TEST_TYPE_S64;

typedef struct c_test_type_u64_t {
   C_TEST_TYPE_HEADER header;

   uint64_t
   expected,
   result;
} C_TEST_TYPE_U64;

typedef struct c_test_type_double_t {
   C_TEST_TYPE_HEADER header;

   double
   expected,
   result,
   delta;
} C_TEST_TYPE_DOUBLE;

typedef struct c_test_type_byte_t {
   C_TEST_TYPE_HEADER header;

   void
   *expected,
   *result;

   size_t size;

} C_TEST_TYPE_BYTE;

typedef struct c_test_type_string_t {
   C_TEST_TYPE_HEADER header;

   const char
   *expected,
   *result;
} C_TEST_TYPE_STRING;

typedef struct c_test_type_nullable_t {
   C_TEST_TYPE_HEADER header;

   void
   *pointer;
//TODO
} C_TEST_TYPE_NULLABLE, C_TEST_TYPE_FAIL;

#define C_TEST_VARGS_SETTER (uint32_t)(0x043E4992)
#define C_TEST_VARGS_SETTER_CHK_SUM (uint32_t)(0x1bc1eeb8)

const uint32_t C_TEST_VARGS_MSG_SIGS[] = {
   C_TEST_VARGS_TITLE, C_TEST_VARGS_INFO, C_TEST_VARGS_WARNING,
   C_TEST_VARGS_ERROR, C_TEST_VARGS_SUCCESS, C_TEST_VARGS_ON_SUCCESS_CALLBACK,
   C_TEST_VARGS_ON_ERROR_CALLBACK
};

#define C_TEST_VARGS_MSG_SIGS_SIZE (sizeof(C_TEST_VARGS_MSG_SIGS)/sizeof(C_TEST_VARGS_MSG_SIGS[0]))

typedef struct c_test_vargs_msg_t {
   uint32_t sig;
   int msg_sz;
   char *msg;

   void
   *ctx;

   cb_fn
   on_success_cb,
   on_error_cb;
} C_TEST_VARGS_MSG;

typedef struct c_test_vargs_msg_header_t {
   uint32_t sig;
   uint32_t sig_chk;
   C_TEST_VARGS_MSG *vargs_msgs[C_TEST_VARGS_MSG_SIGS_SIZE+1];
} C_TEST_VARGS_MSG_HEADER;

static C_TEST_VARGS_MSG *check_vargs_sigmsg_exists(C_TEST_VARGS_MSG **, uint32_t);

#define ASSERT_EQ_INT_FN "assert_equal_int"
#define ASSERT_TRUE_FN "assert_true"
#define ASSERT_FALSE_FN "assert_false"
#define ASSERT_EQUAL_LONG_INT "assert_equal_longint"
#define ASSERT_EQUAL_UNSIGNED_LONG_INT "assert_equal_unsigned_longint"
#define ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT "assert_not_equal_unsigned_longint"
#define ASSERT_EQUAL_DOUBLE "assert_equal_double"
#define ASSERT_EQUAL_BYTE "assert_equal_byte"
#define ASSERT_NOT_EQUAL_INT_FN "assert_not_equal"
#define ASSERT_NOT_EQUAL_LONG_INT "assert_not_equal_longint"
#define ASSERT_NOT_EQUAL_DOUBLE "assert_not_equal_double"
#define ASSERT_NOT_EQUAL_BYTE "assert_not_equal_byte"
#define ASSERT_EQUAL_STRING "assert_equal_string"
#define ASSERT_NOT_EQUAL_STRING "assert_not_equal_string"
#define ASSERT_EQUAL_STRING_IGNORE_CASE "assert_equal_string_ignore_case"
#define ASSERT_NOT_EQUAL_STRING_IGNORE_CASE "assert_not_equal_string_ignore_case"
#define ASSERT_NULL "assert_null"
#define ASSERT_NOT_NULL "assert_not_null"
#define ASSERT_EQUAL_U8 "assert_equal_u8"
#define ASSERT_NOT_EQUAL_U8 "assert_not_equal_u8"
#define ASSERT_EQUAL_S8 "assert_equal_s8"
#define ASSERT_NOT_EQUAL_S8 "assert_not_equal_s8"
#define ASSERT_EQUAL_U16 "assert_equal_u16"
#define ASSERT_NOT_EQUAL_U16 "assert_not_equal_u16"
#define ASSERT_EQUAL_S16 "assert_equal_s16"
#define ASSERT_NOT_EQUAL_S16 "assert_not_equal_s16"
#define ASSERT_EQUAL_U32 "assert_equal_u32"
#define ASSERT_NOT_EQUAL_U32 "assert_not_equal_u32"
#define ASSERT_EQUAL_S32 "assert_equal_s32"
#define ASSERT_NOT_EQUAL_S32 "assert_not_equal_s32"
#define ASSERT_EQUAL_U64 "assert_equal_u64"
#define ASSERT_NOT_EQUAL_U64 "assert_not_equal_u64"
#define ASSERT_EQUAL_S64 "assert_equal_s64"
#define ASSERT_NOT_EQUAL_S64 "assert_not_equal_s64"
// TODO
#define ASSERT_FAIL "assert_fail"

enum type_assert_e {
   TYPE_ASSERT_EQUAL_INT=0,
   TYPE_ASSERT_TRUE,
   TYPE_ASSERT_FALSE,
   TYPE_ASSERT_EQUAL_LONG_INT,
   TYPE_ASSERT_EQUAL_DOUBLE,
   TYPE_ASSERT_EQUAL_BYTE,
   TYPE_ASSERT_NOT_EQUAL_INT,
   TYPE_ASSERT_NOT_EQUAL_LONG_INT,
   TYPE_ASSERT_NOT_EQUAL_DOUBLE,
   TYPE_ASSERT_NOT_EQUAL_BYTE,
   TYPE_ASSERT_EQUAL_STRING,
   TYPE_ASSERT_NOT_EQUAL_STRING,
   TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE,
   TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE,
   TYPE_ASSERT_NULL,
   TYPE_ASSERT_NOT_NULL,
   TYPE_ASSERT_EQUAL_U8,
   TYPE_ASSERT_NOT_EQUAL_U8,
   TYPE_ASSERT_EQUAL_S8,
   TYPE_ASSERT_NOT_EQUAL_S8,
   TYPE_ASSERT_EQUAL_U16,
   TYPE_ASSERT_NOT_EQUAL_U16,
   TYPE_ASSERT_EQUAL_S16,
   TYPE_ASSERT_NOT_EQUAL_S16,
   TYPE_ASSERT_EQUAL_U32,
   TYPE_ASSERT_NOT_EQUAL_U32,
   TYPE_ASSERT_EQUAL_S32,
   TYPE_ASSERT_NOT_EQUAL_S32,
   TYPE_ASSERT_EQUAL_U64,
   TYPE_ASSERT_NOT_EQUAL_U64,
   TYPE_ASSERT_EQUAL_S64,
   TYPE_ASSERT_NOT_EQUAL_S64,
   TYPE_ASSERT_EQUAL_UNSIGNED_LONG_INT,
   TYPE_ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT,
   //TODO
   TYPE_ASSERT_FAIL
};

static C_TEST_FN_DESCRIPTION _tst_fn_desc[] = {
   {TYPE_ASSERT_EQUAL_INT, ASSERT_EQ_INT_FN, sizeof(C_TEST_TYPE_INT), print_assert_int},
   {TYPE_ASSERT_TRUE, ASSERT_TRUE_FN, sizeof(C_TEST_TYPE_BOOL), print_assert_int},
   {TYPE_ASSERT_FALSE, ASSERT_FALSE_FN, sizeof(C_TEST_TYPE_BOOL), print_assert_int},
   {TYPE_ASSERT_EQUAL_LONG_INT, ASSERT_EQUAL_LONG_INT, sizeof(C_TEST_TYPE_LONG_INT), print_assert_longint},
   {TYPE_ASSERT_EQUAL_DOUBLE, ASSERT_EQUAL_DOUBLE, sizeof(C_TEST_TYPE_DOUBLE), print_assert_double},
   {TYPE_ASSERT_EQUAL_BYTE, ASSERT_EQUAL_BYTE, sizeof(C_TEST_TYPE_BYTE), print_assert_byte},
   {TYPE_ASSERT_NOT_EQUAL_INT, ASSERT_NOT_EQUAL_INT_FN, sizeof(C_TEST_TYPE_INT), print_assert_int},
   {TYPE_ASSERT_NOT_EQUAL_LONG_INT, ASSERT_NOT_EQUAL_LONG_INT, sizeof(C_TEST_TYPE_LONG_INT), print_assert_longint},
   {TYPE_ASSERT_NOT_EQUAL_DOUBLE, ASSERT_NOT_EQUAL_DOUBLE, sizeof(C_TEST_TYPE_DOUBLE), print_assert_double},
   {TYPE_ASSERT_NOT_EQUAL_BYTE, ASSERT_NOT_EQUAL_BYTE, sizeof(C_TEST_TYPE_BYTE), print_assert_byte},
   {TYPE_ASSERT_EQUAL_STRING, ASSERT_EQUAL_STRING, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NOT_EQUAL_STRING, ASSERT_NOT_EQUAL_STRING, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE, ASSERT_EQUAL_STRING_IGNORE_CASE, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE, ASSERT_NOT_EQUAL_STRING_IGNORE_CASE, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NULL, ASSERT_NULL, sizeof(C_TEST_TYPE_NULLABLE), print_assert_nullable},
   {TYPE_ASSERT_NOT_NULL, ASSERT_NOT_NULL, sizeof(C_TEST_TYPE_NULLABLE), print_assert_nullable},
   {TYPE_ASSERT_EQUAL_U8, ASSERT_EQUAL_U8, sizeof(C_TEST_TYPE_U8), print_assert_u8},
   {TYPE_ASSERT_NOT_EQUAL_U8, ASSERT_NOT_EQUAL_U8, sizeof(C_TEST_TYPE_U8), print_assert_u8},
   {TYPE_ASSERT_EQUAL_S8, ASSERT_EQUAL_S8, sizeof(C_TEST_TYPE_S8), print_assert_s8},
   {TYPE_ASSERT_NOT_EQUAL_S8, ASSERT_NOT_EQUAL_S8, sizeof(C_TEST_TYPE_S8), print_assert_s8},
   {TYPE_ASSERT_EQUAL_U16, ASSERT_EQUAL_U16, sizeof(C_TEST_TYPE_U16), print_assert_u16},
   {TYPE_ASSERT_NOT_EQUAL_U16, ASSERT_NOT_EQUAL_U16, sizeof(C_TEST_TYPE_U16), print_assert_u16},
   {TYPE_ASSERT_EQUAL_S16, ASSERT_EQUAL_S16, sizeof(C_TEST_TYPE_S16), print_assert_s16},
   {TYPE_ASSERT_NOT_EQUAL_S16, ASSERT_NOT_EQUAL_S16, sizeof(C_TEST_TYPE_S16), print_assert_s16},
   {TYPE_ASSERT_EQUAL_U32, ASSERT_EQUAL_U32, sizeof(C_TEST_TYPE_U32), print_assert_u32},
   {TYPE_ASSERT_NOT_EQUAL_U32, ASSERT_NOT_EQUAL_U32, sizeof(C_TEST_TYPE_U32), print_assert_u32},
   {TYPE_ASSERT_EQUAL_S32, ASSERT_EQUAL_S32, sizeof(C_TEST_TYPE_S32), print_assert_s32},
   {TYPE_ASSERT_NOT_EQUAL_S32, ASSERT_NOT_EQUAL_S32, sizeof(C_TEST_TYPE_S32), print_assert_s32},
   {TYPE_ASSERT_EQUAL_U64, ASSERT_EQUAL_U64, sizeof(C_TEST_TYPE_U64), print_assert_u64},
   {TYPE_ASSERT_NOT_EQUAL_U64, ASSERT_NOT_EQUAL_U64, sizeof(C_TEST_TYPE_U64), print_assert_u64},
   {TYPE_ASSERT_EQUAL_S64, ASSERT_EQUAL_S64, sizeof(C_TEST_TYPE_S64), print_assert_s64},
   {TYPE_ASSERT_NOT_EQUAL_S64, ASSERT_NOT_EQUAL_S64, sizeof(C_TEST_TYPE_S64), print_assert_s64},
   {TYPE_ASSERT_EQUAL_UNSIGNED_LONG_INT, ASSERT_EQUAL_UNSIGNED_LONG_INT, sizeof(C_TEST_TYPE_UNSIGNED_LONG_INT), print_assert_unsigned_longint},
   {TYPE_ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT, ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT, sizeof(C_TEST_TYPE_UNSIGNED_LONG_INT), print_assert_unsigned_longint},
   {TYPE_ASSERT_FAIL, ASSERT_FAIL, sizeof(C_TEST_TYPE_FAIL), print_assert_fail}
};

#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_INT _tst_fn_desc[TYPE_ASSERT_EQUAL_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_TRUE _tst_fn_desc[TYPE_ASSERT_TRUE]
#define C_TEST_FN_DESCRIPTION_ASSERT_FALSE _tst_fn_desc[TYPE_ASSERT_FALSE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_LONG_INT _tst_fn_desc[TYPE_ASSERT_EQUAL_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_UNSIGNED_LONG_INT _tst_fn_desc[TYPE_ASSERT_EQUAL_UNSIGNED_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_UNSIGNED_LONG_INT _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_DOUBLE _tst_fn_desc[TYPE_ASSERT_EQUAL_DOUBLE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_BYTE _tst_fn_desc[TYPE_ASSERT_EQUAL_BYTE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_INT _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_LONG_INT _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_DOUBLE _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_DOUBLE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_BYTE _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_BYTE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING _tst_fn_desc[TYPE_ASSERT_EQUAL_STRING]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_STRING]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING_IGNORE_CASE _tst_fn_desc[TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING_IGNORE_CASE _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NULL _tst_fn_desc[TYPE_ASSERT_NULL]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_NULL _tst_fn_desc[TYPE_ASSERT_NOT_NULL]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_U8 _tst_fn_desc[TYPE_ASSERT_EQUAL_U8]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U8 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_U8]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_S8 _tst_fn_desc[TYPE_ASSERT_EQUAL_S8]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S8 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_S8]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_U16 _tst_fn_desc[TYPE_ASSERT_EQUAL_U16]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U16 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_U16]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_S16 _tst_fn_desc[TYPE_ASSERT_EQUAL_S16]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S16 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_S16]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_U32 _tst_fn_desc[TYPE_ASSERT_EQUAL_U32]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U32 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_U32]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_S32 _tst_fn_desc[TYPE_ASSERT_EQUAL_S32]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S32 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_S32]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_U64 _tst_fn_desc[TYPE_ASSERT_EQUAL_U64]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U64 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_U64]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_S64 _tst_fn_desc[TYPE_ASSERT_EQUAL_S64]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S64 _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_S64]
//TODO
#define C_TEST_FN_DESCRIPTION_ASSERT_FAIL _tst_fn_desc[TYPE_ASSERT_FAIL]

typedef union c_test_fn {
   C_TEST_FN_META meta;
   C_TEST_TYPE_INT tst_eq_int;
   C_TEST_TYPE_BOOL tst_eq_bool;
   C_TEST_TYPE_LONG_INT tst_eq_longint;
   C_TEST_TYPE_DOUBLE tst_eq_double;
   C_TEST_TYPE_BYTE tst_eq_byte;
   C_TEST_TYPE_STRING tst_eq_string;
   C_TEST_TYPE_NULLABLE tst_eq_null;
   C_TEST_TYPE_U8 tst_eq_u8;
   C_TEST_TYPE_S8 tst_eq_s8;
   C_TEST_TYPE_U16 tst_eq_u16;
   C_TEST_TYPE_S16 tst_eq_s16;
   C_TEST_TYPE_U32 tst_eq_u32;
   C_TEST_TYPE_S32 tst_eq_s32;
   C_TEST_TYPE_U64 tst_eq_u64;
   C_TEST_TYPE_S64 tst_eq_s64;
   C_TEST_TYPE_UNSIGNED_LONG_INT tst_eq_unsigned_longint;
   //TODO
   C_TEST_TYPE_FAIL tst_fail;
} C_TEST_FN;

#define PRINTF_FINAL_FMT printf("%.*s", err, msg);
void write_title(const char *message, const char *template)
{
   int err;
   char *msg;

   if (!message) {
      printf("Missing message");
      abort_tests();
   }

   if ((err=asprintf(&msg, "%s%s%s\n", template, message, END_TITLE))<0) {
      printf("Message error");
      abort_tests();
   }

   PRINTF_FINAL_FMT

   free(msg);
}

void write_title_fmt(const char *template, const char *fmt, ...)
{
   int err;
   char *msg_fmt, *msg;
   va_list args;

   if (!fmt) {
      printf("Missing format at \"write_title_fmt\"");
      abort_tests();
   }

   va_start(args, fmt);
   err=vasprintf(&msg_fmt, fmt, args);
   va_end(args);

   if (err<0) {
      printf("Message format error at \"write_title_fmt\"");
      abort_tests();
   }

   err=asprintf(&msg, "%s%.*s%s\n", template, err, msg_fmt, END_TITLE);

   free(msg_fmt);

   if (err<0) {
      printf("Final message error at \"write_title_fmt\"");
      abort_tests();
   }

   PRINTF_FINAL_FMT

   free(msg);
}

inline static void end_test_msg_util(size_t tst)
{
   if (tst)
      WARN_MSG_FMT("WARNING: %d test(s) ignored", tst)
}

static void end_tests_util(int abort)
{
   time_t t;

   if (_c_test_ptr) {
      t=time(NULL);

      if (abort) {
         if (((C_TEST_HEADER *)_c_test_ptr)->on_abort_fn)
            ((C_TEST_HEADER *)_c_test_ptr)->on_abort_fn(_c_test_ptr);

         end_test_msg_util(((C_TEST_HEADER *)_c_test_ptr)->ignored);

         ERROR_MSG_FMT(
            "Aborting TESTS.\nAt %s\nTotal: %d\nTest(s): %d finished", ctime(&t), ((C_TEST_HEADER *)_c_test_ptr)->next,
             ((C_TEST_HEADER *)_c_test_ptr)->next-((C_TEST_HEADER *)_c_test_ptr)->ignored
         )

      } else {
         if (((C_TEST_HEADER *)_c_test_ptr)->on_end_test_fn)
            ((C_TEST_HEADER *)_c_test_ptr)->on_end_test_fn(_c_test_ptr);

         end_test_msg_util(((C_TEST_HEADER *)_c_test_ptr)->ignored);

         TITLE_MSG_FMT(
            "*** END TESTS ***\nTotal: %d\nTest(s): %d\nAt: %s", ((C_TEST_HEADER *)_c_test_ptr)->tests, 
            ((C_TEST_HEADER *)_c_test_ptr)->next-((C_TEST_HEADER *)_c_test_ptr)->ignored, ctime(&t)
         )

         TITLE_MSG_FMT("Total time: %llu\n", (uint64_t)t-((C_TEST_HEADER *)_c_test_ptr)->initial_timestamp)
      }

      if (((C_TEST_HEADER *)_c_test_ptr)->tests)
         memset(_c_test_ptr+sizeof(C_TEST_HEADER), 0, (((C_TEST_HEADER *)_c_test_ptr)->tests)*sizeof(C_TEST_FN));

      memset(_c_test_ptr, 0, sizeof(C_TEST_HEADER));
      free(_c_test_ptr);
      _c_test_ptr=NULL;

   } else if (abort)
      ERROR_MSG("\nERROR: Null pointer. Probably you start ctest with invalid argument. Aborting C test.\n")
   else
      WARN_MSG("\nWARNING: Null pointer. Probably you start ctest with invalid argument. Ignoring ...\n")
}

void end_tests() { end_tests_util(0); }

static void abort_tests() {
   end_tests_util(1);
   exit(1);
}

void _c_test_ignore()
{
   c_test_not_ignored=C_TEST_FALSE;
}

void _c_test_ignore_end()
{
   c_test_not_ignored=C_TEST_TRUE;
}

static void begin_test(void *vas)
{
   C_TEST_FN *p, *q;
   time_t t;

   p=((C_TEST_FN *)(_c_test_ptr+sizeof(C_TEST_HEADER)));

   t=time(NULL);

   if (!((C_TEST_HEADER *)_c_test_ptr)->next) {
      ((C_TEST_HEADER *)_c_test_ptr)->initial_timestamp=(uint64_t)t;
      TITLE_MSG_FMT("*** BEGIN TEST ***\nAt: %s", ctime(&t))

      if (((C_TEST_HEADER *)_c_test_ptr)->on_begin_test_fn)
         ((C_TEST_HEADER *)_c_test_ptr)->on_begin_test_fn(_c_test_ptr);

   }

   q=&p[((C_TEST_HEADER *)_c_test_ptr)->next++];

   if (c_test_not_ignored) {
      TITLE_MSG_FMT("Testing %d -> \"%s\" (%p)...", ((C_TEST_HEADER *)_c_test_ptr)->next, q->meta.fn_name, q)
      q->meta.cb(q, vas);
      TITLE_MSG_FMT("Duration (ms): %llu\n", (uint64_t)time(NULL)-t)

   } else {
      free_vargs(vas);
      ((C_TEST_HEADER *)_c_test_ptr)->ignored++;
      WARN_MSG_FMT("WARNING: Ignoring %d -> \"%s\" (%p)...", ((C_TEST_HEADER *)_c_test_ptr)->next, q->meta.fn_name, q)

   }
}

#define C_TEST_INITIAL_ADD \
   ((C_TEST_HEADER *)p)->signature=C_TEST_HEADER_SIGNATURE;\
   ((C_TEST_HEADER *)p)->tests=0U;\
   ((C_TEST_HEADER *)p)->next=0U;\
   ((C_TEST_HEADER *)p)->ignored=0U;\
   ((C_TEST_HEADER *)p)->initial_timestamp=0UL;\
   ((C_TEST_HEADER *)p)->final_timestamp=0UL;

#define C_TEST_ON_ADD_FN(fn) ((C_TEST_HEADER *)p)->on_add_test_fn=fn;
#define C_TEST_ON_TEST_FN(fn) ((C_TEST_HEADER *)p)->on_test_fn=fn;
#define C_TEST_ON_BEGIN_FN(fn) ((C_TEST_HEADER *)p)->on_begin_test_fn=fn;
#define C_TEST_ON_END_FN(fn) ((C_TEST_HEADER *)p)->on_end_test_fn=fn;
#define C_TEST_ON_ABORT_FN(fn) ((C_TEST_HEADER *)p)->on_abort_fn=fn;

#define C_TEST_ON_ADD_FN_POINTER ((C_TEST_HEADER *)p)->on_add_test_fn
#define C_TEST_ON_BEGIN_FN_POINTER ((C_TEST_HEADER *)p)->on_begin_test_fn
#define C_TEST_ON_TEST_FN_POINTER ((C_TEST_HEADER *)p)->on_test_fn
#define C_TEST_ON_END_FN_POINTER ((C_TEST_HEADER *)p)->on_end_test_fn
#define C_TEST_ON_ABORT_FN_POINTER ((C_TEST_HEADER *)p)->on_abort_fn

#define C_TEST_INITIAL_ADD_FN_ALL_NULL \
   C_TEST_ON_ADD_FN(NULL) \
   C_TEST_ON_TEST_FN(NULL) \
   C_TEST_ON_BEGIN_FN(NULL) \
   C_TEST_ON_END_FN(NULL) \
   C_TEST_ON_ABORT_FN(NULL)

#define ON_TEST_WARN1 "WARNING: %s callback already exists at pointer (%p). Overwriting with a new callback pointer (%p)"
#define ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(fn_name, ptr) \
   if (ptr) \
      WARN_MSG_FMT(ON_TEST_WARN1, fn_name, ptr, fn);

#define ON_ADD_TEST_STR "on_add_test()"
void on_add_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_add_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_add_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)
      C_TEST_ON_ADD_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_ADD_TEST_STR, C_TEST_ON_ADD_FN_POINTER)

   C_TEST_ON_ADD_FN(fn)

   #undef p
}

#define RM_ON_TEST_WARN1 "WARNING: %s without %s. Ignoring ..." 
#define RM_ON_TEST_WARN2 "WARNING: %s may be NOT initialized. Ignoring ..."
#define RM_ON_ADD_TEST_STR "rm_on_add_test()"
void rm_on_add_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_ADD_FN_POINTER)
         C_TEST_ON_ADD_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_ADD_TEST_STR, ON_ADD_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_ADD_TEST_STR)

   #undef p
}

#define ON_BEGIN_TEST_STR "on_begin_test()"
void on_begin_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_begin_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_begin_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_BEGIN_TEST_STR, C_TEST_ON_BEGIN_FN_POINTER)

   C_TEST_ON_BEGIN_FN(fn)

   #undef p
}

#define RM_ON_BEGIN_TEST_STR "rm_begin_test()"
void rm_begin_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_BEGIN_FN_POINTER)
         C_TEST_ON_BEGIN_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_BEGIN_TEST_STR, ON_BEGIN_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_BEGIN_TEST_STR)

   #undef p
}

#define ON_TEST_STR "on_test()"
void on_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_TEST_STR, C_TEST_ON_TEST_FN_POINTER)

   C_TEST_ON_TEST_FN(fn)

   #undef p
}

#define RM_ON_TEST_TEST_STR "rm_on_test()"
void rm_on_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_TEST_FN_POINTER)
         C_TEST_ON_TEST_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_TEST_TEST_STR, ON_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_TEST_STR)

   #undef p
}

#define ON_END_TEST_STR "on_end_test()"
void on_end_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_end_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_end_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)
      C_TEST_ON_END_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_END_TEST_STR, C_TEST_ON_END_FN_POINTER)

   C_TEST_ON_END_FN(fn)

   #undef p
}

#define RM_ON_END_TEST_STR "rm_on_end_test()"
void rm_on_end_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_END_FN_POINTER)
         C_TEST_ON_END_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_END_TEST_STR, ON_END_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_END_TEST_STR)

   #undef p
}

#define ON_ABORT_STR "on_abort()"
void on_abort(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_abort missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_abort missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_ABORT_STR, C_TEST_ON_ABORT_FN_POINTER)

   C_TEST_ON_ABORT_FN(fn)

   #undef p
}

#define RM_ON_ABORT_STR "rm_abort()"
void rm_abort()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_ABORT_FN_POINTER)
         C_TEST_ON_ABORT_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_ABORT_STR, ON_ABORT_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_ABORT_STR)

   #undef p
}
//
// memory sanitizer check
_Static_assert(sizeof(int)>=sizeof(uint32_t), "Processor architecture should be 32 bit or more");
//
#define C_VARGS_SZ sizeof(C_TEST_VARGS_MSG_HEADER)
static inline int c_test_is_header_invalid(C_TEST_VARGS_MSG_HEADER *header)
{

   if (header->sig^C_TEST_VARGS_SETTER)
      return -2;

   if (header->sig_chk^C_TEST_VARGS_SETTER_CHK_SUM)
      return -3;

   return 0;
//   return ((header->sig^C_TEST_VARGS_SETTER)|(header->sig_chk^C_TEST_VARGS_SETTER_CHK_SUM)); // Memory sanity check
}

static C_TEST_VARGS_MSG_HEADER *c_test_vargs_create()
{
   void *c_vargs;

   if (!(c_vargs=malloc(C_VARGS_SZ)))
      return NULL;

   ((C_TEST_VARGS_MSG_HEADER *)c_vargs)->sig=C_TEST_VARGS_SETTER;
   ((C_TEST_VARGS_MSG_HEADER *)c_vargs)->sig_chk=C_TEST_VARGS_SETTER_CHK_SUM;
   memset(((C_TEST_VARGS_MSG_HEADER *)c_vargs)->vargs_msgs, 0, sizeof(C_TEST_VARGS_MSG *)*(C_TEST_VARGS_MSG_SIGS_SIZE+1));
   return (C_TEST_VARGS_MSG_HEADER *)c_vargs;
}

static C_TEST_VARGS_MSG *check_vargs_sigmsg_exists(C_TEST_VARGS_MSG **test_vargs_msg, uint32_t sig)
{
   C_TEST_VARGS_MSG **p;

   p=test_vargs_msg;

   for (;(*p);p++)
      if ((*p)->sig==sig)
         return (*p);

   return NULL;
}

static uint32_t check_msgsig(C_TEST_VARGS_MSG *va_msg)
{
   uint32_t i=0;

   if (!va_msg)
      return 0;

   for (;i<C_TEST_VARGS_MSG_SIGS_SIZE;)
      if (va_msg->sig==C_TEST_VARGS_MSG_SIGS[i++])
         return va_msg->sig;

   return 0;
}

static int free_vargs(void *vargs)
{
   int err;
   C_TEST_VARGS_MSG **p;

   if (!vargs)
      return 0;

   err=0;
   p=((C_TEST_VARGS_MSG_HEADER *)vargs)->vargs_msgs;

   while (*p) {
      if (!check_msgsig(*p)) {
         p++;
         err=7;
         ERROR_MSG("ERROR: check_msgsig(). Missing or invalid message signature. Maybe wrong parameters. Ignoring free argument")
         continue;
      }

      if ((*p)->sig&C_TEST_TYPE_VARGS_MSG) {
         if ((*p)->msg_sz>=0) {
            if ((*p)->msg)
               free((*p)->msg);
         } else
            ERROR_MSG_FMT("ERROR %d: free_vargs(). Error dealloc message. Signature = %04x at address = (%p)", (err=(*p)->msg_sz), (*p)->sig, (*p))

      } else {
         (*p)->ctx=NULL;
         (*p)->on_success_cb=NULL;
         (*p)->on_error_cb=NULL;
      }

      free(*(p++));
   }

   free(memset(vargs, 0, C_VARGS_SZ));

   return err;
}

#define CLOSE_VARG_ERR_NULL (int)8
#define CLOSE_VARG_ERR_WRONG_SIG (int)9
static int close_varg(C_TEST_VARGS_MSG *varg)
{
   int err;

   if (!varg) {
      WARN_MSG("WARNING: close_varg() is NULL. Ignoring closing parameter")
      return CLOSE_VARG_ERR_NULL;
   }

   if (!check_msgsig(varg)) {
      WARN_MSG_FMT("WARNING: check_msgsig() @ close_varg. Signature not found in address (%p). Ignoring closing", (void *)varg)
      return CLOSE_VARG_ERR_WRONG_SIG;
   }

   err=0;

   if (varg->sig&C_TEST_TYPE_VARGS_MSG) {
      if (varg->msg_sz>=0) {
         if (varg->msg)
            free(varg->msg);

      } else
         WARN_MSG_FMT(
            "WARNING %d: close_varg(). Message may be a wrong format at address (%p). Closing vargs...",
             err=varg->msg_sz,
             (void *)varg
         )
   } else if (varg->sig&C_TEST_TYPE_VARGS_CALLBACK) {
      varg->ctx=NULL;
      varg->on_success_cb=NULL;
      varg->on_error_cb=NULL;
   } else
      WARN_MSG("WARNING: close_varg(). Unknown argument type. Ignoring and close ...");

   free(varg);

   return err;
}

void *set_varg(uint32_t sig, const char *message, ...)
{
   C_TEST_VARGS_MSG *varg_tmp;
   va_list args;

   if ((sig&C_TEST_TYPE_VARGS_MSG)==0)
      return NULL;

   if (!(varg_tmp=malloc(sizeof(C_TEST_VARGS_MSG))))
      return NULL;

   memset(varg_tmp, 0, sizeof(C_TEST_VARGS_MSG));

   varg_tmp->sig=sig;
   va_start(args, message);
   varg_tmp->msg_sz=vasprintf(&varg_tmp->msg, message, args);
   va_end(args);

   return (void *)varg_tmp;
}

void *set_varg_callback(uint32_t sig, cb_fn callback, ...)
{
   C_TEST_VARGS_MSG *varg_tmp;
   va_list args;

   if ((sig&C_TEST_TYPE_VARGS_CALLBACK)==0) {
      ERROR_MSG("ERROR: Invalid argument callback signature")
      return NULL;
   }

   if (!callback) {
      ERROR_MSG("ERROR: Missing callback function")
      return NULL;
   }

   if (!(varg_tmp=malloc(sizeof(C_TEST_VARGS_MSG)))) {
      ERROR_MSG("FATAL: error callback malloc")
      return NULL;
   }

   memset(varg_tmp, 0, sizeof(C_TEST_VARGS_MSG));

   if ((varg_tmp->sig=sig)==C_TEST_VARGS_ON_SUCCESS_CALLBACK)
      varg_tmp->on_success_cb=callback;
   else
      varg_tmp->on_error_cb=callback;

   va_start(args, callback);
   if ((varg_tmp->ctx=(void *)va_arg(args, void *)))
      if ((void *)va_arg(args, void *)!=NULL)
         if ((void *)va_arg(args, void *)!=VAS_END_SIGNATURE) {
            ERROR_MSG("ERROR: Missing END argument");
            free(varg_tmp);
            varg_tmp=NULL;
         }

   va_end(args);

   return (void *)varg_tmp;
}

#define VARG_ERROR_MSG_NULL_PARM "ERROR: CTEST_SETTER has NULL parameter at argument %d."
#define VARG_ERROR_MSG_MANY_ARGUMENTS "ERROR: CTEST_SETTER has too many arguments"
void *vargs_setter(int initial, ...)
{
   int err, argc;
   void *v;
   va_list args, args_cpy;
   C_TEST_VARGS_MSG_HEADER *ret;
   C_TEST_VARGS_MSG **vargs_msgs;

   if (initial!=-1) {
      ERROR_MSG("ERROR: Initial value is wrong. Please consider use \"CTEST_SETTER\" instead. Ignoring parameter ...")
      return NULL;
   }

   err=0;
   argc=0;

   va_start(args, initial);
   va_copy(args_cpy, args);
#define MAX_ARG_OVF (size_t)C_TEST_VARGS_MSG_SIGS_SIZE+2
   while ((argc++)<(MAX_ARG_OVF+1)) {

      if (argc>MAX_ARG_OVF) {
         argc--;
         err=-3;
         ERROR_MSG(VARG_ERROR_MSG_MANY_ARGUMENTS)
         break;
      }

      if ((v=(void *)va_arg(args, void *))==VA_END_SIGNATURE)
         break;

      if (!v) {

         argc++;

         if (argc>MAX_ARG_OVF) {
            argc--;
            err=-5;
            ERROR_MSG(VARG_ERROR_MSG_MANY_ARGUMENTS)
            break;
         }

         if ((v=(void *)va_arg(args, void *))==VA_END_SIGNATURE)
            break;

         err=-1;
         ERROR_MSG_FMT(VARG_ERROR_MSG_NULL_PARM, argc-1)

         if (v)
            goto while_vargs_continue;

         if ((MAX_ARG_OVF-2)>argc)
            ERROR_MSG_FMT(VARG_ERROR_MSG_NULL_PARM, argc)

      }

while_vargs_continue:
      if ((MAX_ARG_OVF-2)>=argc)
         if (!check_msgsig((C_TEST_VARGS_MSG *)v)) {
            err=-4;
            ERROR_MSG_FMT("ERROR: Invalid message at argument %d", argc)
         }
   }
   va_end(args);

   if (argc>2)
      argc-=2;
   else if (argc==2) {
      if (!err)
         return (C_TEST_VARGS_MSG_HEADER *)VA_END_SIGNATURE;

      ERROR_MSG_FMT("ERROR %d: Invalid empty args", err);
      return NULL;
   } else {
      ERROR_MSG("ERROR: vargs_setter must be initialized only with CTEST_SETTER macro.");
      return NULL;
   }

   va_copy(args, args_cpy);
   va_start(args, initial);
   if (err) {
      ret=NULL;

vargs_setter_RET:
      ERROR_MSG_FMT("Error(s) occurred with last error %d. Closing arguments before quit ...", err);

      for (initial=0;initial<argc;initial++) {
         INFO_MSG_FMT("Closing argument %d ...", initial)
         if ((err=close_varg((C_TEST_VARGS_MSG *)(v=(void *)va_arg(args, void *))))) {
            if (err==CLOSE_VARG_ERR_WRONG_SIG)
               if (!c_test_is_header_invalid((C_TEST_VARGS_MSG_HEADER *)v)) {
                  ERROR_MSG("Error: Found forbidden arguments inside argument setter. Trying to close");

                  if ((err=free_vargs((C_TEST_VARGS_MSG_HEADER *)v))) ERROR_MSG_FMT("Error %d: Closing failed", err)
                  else INFO_MSG("Closed success!");
               }

         } else
            SUCCESS_MSG_FMT("Argument %d closed", initial)

      }

      if (ret) {
         SUCCESS_MSG_FMT("Finally close vargs handler at address (%p)", ret)
         free(ret);// All children was cleared using close_varg. Here we will NOT use free_vargs() in this case
      }

      ERROR_MSG("Closed all arguments");
      va_end(args);
      return NULL;
   }

   if (!(ret=c_test_vargs_create())) {
      ERROR_MSG("Fatal: Can't create vargs setter ...")
      goto vargs_setter_EXIT1;
   }

   vargs_msgs=ret->vargs_msgs;

   for (initial=0;initial<argc;initial++) {
      if (check_vargs_sigmsg_exists(ret->vargs_msgs, ((C_TEST_VARGS_MSG *)(v=(void *)va_arg(args, void *)))->sig)) {
         err=-127;
         ERROR_MSG("ERROR: Repeated arguments. Closing ...")
         goto vargs_setter_EXIT1;
      }

      *(vargs_msgs++)=(C_TEST_VARGS_MSG *)v;

   }

   va_end(args);
   return (void *)ret;

vargs_setter_EXIT1:
   va_end(args);
   va_copy(args, args_cpy);
   va_start(args, initial);

   goto vargs_setter_RET;

#undef MAX_ARG_OVF
}

#define LOAD_TEST_VARGS_ERROR_TOO_MANY_ARGS 10
#define LOAD_TEST_VARGS_ERROR_MISSING_ARGUMENTS 11
#define LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_1 12
#define LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_2 13
#define LOAD_TEST_VARGS_ERROR_IS_NULL 14
#define LOAD_TEST_VARGS_ERROR_HEADER_INVALID 15
#define LOAD_TEST_VARGS_END_SIGNATURE -15
static int load_test_vargs(void **vargs, ...)
{
   int i;
   void *ptr[3];
   va_list ap;

#define MAX_ARG 3+1
   *vargs=NULL;
   va_start(ap, vargs);
   for (i=0;i<MAX_ARG;) {
      if (i==(MAX_ARG-1)) {
         va_end(ap);
         return LOAD_TEST_VARGS_ERROR_TOO_MANY_ARGS;
      }
      if ((ptr[i++]=(void *)va_arg(ap, void *))==VAS_END_SIGNATURE)
         break;
   }
   va_end(ap);
#undef MAX_ARG

   if (i==1)
      return LOAD_TEST_VARGS_ERROR_MISSING_ARGUMENTS;

   (i==2)?(i=0):(i=1);

   if (ptr[i++])
      return LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_1;

   if (ptr[i]!=VAS_END_SIGNATURE)
      return LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_2;

   if (ptr[1]==VAS_END_SIGNATURE)
      return LOAD_TEST_VARGS_END_SIGNATURE;

   if (!ptr[0])
      return LOAD_TEST_VARGS_ERROR_IS_NULL;

   if (c_test_is_header_invalid(ptr[0]))
      return LOAD_TEST_VARGS_ERROR_HEADER_INVALID;

   *vargs=(C_TEST_VARGS_MSG_HEADER *)ptr[0];
   return 0;
}

static char *parse_vas_msg(int *msg_sz, void *vas, uint32_t sig)
{
   C_TEST_VARGS_MSG *res;
   char *p;

   *msg_sz=0;

   if (!vas)
      return NULL;

   p=NULL;
   if ((res=check_vargs_sigmsg_exists(((C_TEST_VARGS_MSG_HEADER *)vas)->vargs_msgs, sig)))
      if (res->msg_sz>0) {
         p=res->msg;
         *msg_sz=res->msg_sz;
      }

   return p;
}

static void parse_vas_cb(void *vas, uint32_t sig)
{
   C_TEST_VARGS_MSG *res;

   if (!vas)
      return;

   if ((res=check_vargs_sigmsg_exists(((C_TEST_VARGS_MSG_HEADER *)vas)->vargs_msgs, sig))) {
      if (sig==C_TEST_VARGS_ON_SUCCESS_CALLBACK)
         res->on_success_cb(res->ctx);
      else
         res->on_error_cb(res->ctx);
   }
}

#define CALLBACK_ON_SUCCESS parse_vas_cb(vas, C_TEST_VARGS_ON_SUCCESS_CALLBACK);
#define CALLBACK_ON_ERROR parse_vas_cb(vas, C_TEST_VARGS_ON_ERROR_CALLBACK);

//
#define PRINT_CALLBACK \
   if (((C_TEST_HEADER *)_c_test_ptr)->on_test_fn)\
      ((C_TEST_HEADER *)_c_test_ptr)->on_test_fn(ctx);

#define SHOW_USER_NOTIFICATION \
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_TITLE)))\
      TITLE_MSG_FMT("%.*s", p_sz, p)\
\
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_INFO)))\
      INFO_MSG_FMT("%.*s", p_sz, p)\
\
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_WARNING)))\
      WARN_MSG_FMT("%.*s", p_sz, p)

static void print_assert_int(void *ctx, void *vas)
{
   int error, idx, p_sz;
   uint32_t desc_type;
   char *p;
   C_TEST_TYPE_INT *type=(C_TEST_TYPE_INT *)ctx;

   const char *print_assert_int_msg[][2] = {
      {"\"%s\". FALSE (%d) -> ok", "\"%s\". Expected FALSE (%d), but found TRUE (%d) -> fail"},
      {"\"%s\". TRUE (%d) -> ok", "\"%s\". Expected TRUE (%d), but found FALSE (%d) -> fail"},
      {"\"%s\". Expected %d (0x%08x) == result %d (0x%08x) -> ok", "\"%s\". Expected %d (0x%08x), but found %d (0x%08x) -> fail"},
      {"\"%s\". Unexpected %d (0x%08x) != result %d (0x%08x) -> ok", "\"%s\". Unexpected %d (%08x) == result %d (0x%08x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if ((desc_type=type->header.desc.type)==TYPE_ASSERT_TRUE)
      idx=1;
   else if (desc_type==TYPE_ASSERT_EQUAL_INT)
      idx=2;
   else if (desc_type==TYPE_ASSERT_NOT_EQUAL_INT) {
      error=!error;
      idx=3;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      if (idx>1)
         ERROR_MSG_FMT(print_assert_int_msg[idx][1],
            type->header.desc.fn_name,
            type->expected, type->expected,
            type->result, type->result
        )
      else
         ERROR_MSG_FMT(print_assert_int_msg[idx][1],
            type->header.desc.fn_name,
            type->expected,
            type->result
        )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   if (idx>1)
      SUCCESS_MSG_FMT(print_assert_int_msg[idx][0],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
     )
   else
      SUCCESS_MSG_FMT(print_assert_int_msg[idx][0],
         type->header.desc.fn_name,
         type->expected,
         type->result
     )

}

static void print_assert_longint(void *ctx, void *vas)
{
   C_TEST_TYPE_LONG_INT *type=(C_TEST_TYPE_LONG_INT *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_int_msg[][2] = {
      {"\"%s\". Expected %lld (0x%016llx) == result %lld (0x%016llx) -> ok", "\"%s\". Expected %lld (0x%016llx), but found %lld (0x%016llx) -> fail"},
      {"\"%s\". Unexpected %lld (0x%016llx) != result %lld (0x%016llx) -> ok", "\"%s\". Unexpected %lld (%016llx) == result %lld (0x%016llx) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_LONG_INT) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_int_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_int_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->expected,
      type->result, type->result
   )
}

static void print_assert_unsigned_longint(void *ctx, void *vas)
{
   C_TEST_TYPE_UNSIGNED_LONG_INT *type=(C_TEST_TYPE_UNSIGNED_LONG_INT *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_unsigned_long_int_msg[][2] = {
      {"\"%s\". Expected %llu (0x%016llx) == result %llu (0x%016llx) -> ok", "\"%s\". Expected %llu (0x%016llx), but found %llu (0x%016llx) -> fail"},
      {"\"%s\". Unexpected %llu (0x%016llx) != result %llu (0x%016llx) -> ok", "\"%s\". Unexpected %llu (%016llx) == result %llu (0x%016llx) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_unsigned_long_int_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_unsigned_long_int_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->expected,
      type->result, type->result
   )
}

static void print_assert_double(void *ctx, void *vas)
{
   C_TEST_TYPE_DOUBLE *type=(C_TEST_TYPE_DOUBLE *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_int_msg[][2] = {
      {"\"%s\". Expected %.17g == result %.17g with delta = %e -> ok", "\"%s\". Expected %.17g, but found %.17g with delta = %e -> fail"},
      {"\"%s\". Unexpected %.17g != result %.17g with delta = %e -> ok", "\"%s\". Unexpected %.17g == result %.17g with delta = %e -> fail"}
   };

   PRINT_CALLBACK

   error=(fabs(type->expected-type->result)>fabs(type->delta));

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_DOUBLE) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_int_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->result, type->delta
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_int_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->result, type->delta
   )

}

static void print_assert_byte(void *ctx, void *vas)
{
   C_TEST_TYPE_BYTE *type=(C_TEST_TYPE_BYTE *)ctx;
   int error, idx, p_sz;
   char *p;
//TODO Compatibility to size
   const char *print_assert_byte_msg[][2] = {
      {
          "\"%s\". (%llu) bytes at pointer expected (%p) == pointer result (%p) -> ok",
          "\"%s\". (%llu) bytes at pointer expected (%p) != pointer result (%p) -> fail"
      },
      {
          "\"%s\". (%llu) bytes at pointer unexpected (%p) != pointer result (%p) -> ok", 
          "\"%s\". (%llu) bytes at pointer unexpected (%p) == pointer result (%p) -> fail"
      }
   };

   PRINT_CALLBACK

   error=memcmp(type->expected, type->result, type->size);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_BYTE) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_byte_msg[idx][1],
         type->header.desc.fn_name,
         type->size,
         type->expected, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_byte_msg[idx][0],
      type->header.desc.fn_name,
      type->size,
      type->expected, type->result
   )
}

static void print_assert_string(void *ctx, void *vas)
{
   C_TEST_TYPE_STRING *type=(C_TEST_TYPE_STRING *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_string_msg[][2] = {
      {
          "\"%s\". Expected \"%s\" at pointer (%p) == result \"%s\" at pointer (%p) -> ok",
          "\"%s\". Expected \"%s\" at pointer (%p) != result \"%s\" at pointer (%p) -> fail"
      },
      {
          "\"%s\". Unexpected \"%s\" at pointer (%p) != result \"%s\" at pointer (%p) -> ok", 
          "\"%s\". Unexpected \"%s\" at pointer (%p) == result \"%s\" at pointer (%p) -> fail"
      }
   };

   PRINT_CALLBACK

   error=((type->header.desc.type==TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE)||(type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE))?
         (strcasecmp(type->expected, type->result)):(strcmp(type->expected, type->result));

   idx=0;
   if ((type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING)||(type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE)) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_string_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_string_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->expected,
      type->result, type->result
   )
}

static void print_assert_nullable(void *ctx, void *vas)
{
   C_TEST_TYPE_NULLABLE *type=(C_TEST_TYPE_NULLABLE *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_nullable_msg[][2] = {
      {
          "\"%s\". Expected not NULL. Result (%p) -> ok",
          "\"%s\". Expected not NULL pointer but pointer (%s) found -> fail"
      },
      {
          "\"%s\". Expected NULL == result (%s) -> ok",
          "\"%s\". Expected NULL pointer but pointer (%p) found -> fail"
      }
   };

   PRINT_CALLBACK

   error=(type->pointer==NULL);
   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NULL) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_nullable_msg[idx][1], type->header.desc.fn_name, (type->pointer)?(type->pointer):"NULL")

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_nullable_msg[idx][0], type->header.desc.fn_name, (type->pointer)?(type->pointer):"NULL")
}

static void print_assert_u8(void *ctx, void *vas)
{
   C_TEST_TYPE_U8 *type=(C_TEST_TYPE_U8 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_u8[][2] = {
      {"\"%s\". Expected %u (0x%02x) == result %u (0x%02x) -> ok", "\"%s\". Expected %u (0x%02x), but found %u (0x%02x) -> fail"},
      {"\"%s\". Unexpected %u (0x%02x) != result %u (0x%02x) -> ok", "\"%s\". Unexpected %u (%02x) == result %u (0x%02x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_U8) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_u8[idx][1],
         type->header.desc.fn_name,
         (unsigned int)type->expected, type->expected,
         (unsigned int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_u8[idx][0],
      type->header.desc.fn_name,
      (unsigned int)type->expected, type->expected,
      (unsigned int)type->result, type->result
   )
}

static void print_assert_s8(void *ctx, void *vas)
{
   C_TEST_TYPE_S8 *type=(C_TEST_TYPE_S8 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_s8[][2] = {
      {"\"%s\". Expected %d (0x%02x) == result %d (0x%02x) -> ok", "\"%s\". Expected %d (0x%02x), but found %d (0x%02x) -> fail"},
      {"\"%s\". Unexpected %d (0x%02x) != result %d (0x%02x) -> ok", "\"%s\". Unexpected %d (%02x) == result %d (0x%02x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_S8) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_s8[idx][1],
         type->header.desc.fn_name,
         (signed int)type->expected, type->expected&0xFF,
         (signed int)type->result, type->result&0xFF
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_s8[idx][0],
      type->header.desc.fn_name,
      (signed int)type->expected, type->expected&0xFF,
      (signed int)type->result, type->result&0xFF
   )
}

static void print_assert_u16(void *ctx, void *vas)
{
   C_TEST_TYPE_U16 *type=(C_TEST_TYPE_U16 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_u16[][2] = {
      {"\"%s\". Expected %u (0x%04x) == result %u (0x%04x) -> ok", "\"%s\". Expected %u (0x%04x), but found %u (0x%04x) -> fail"},
      {"\"%s\". Unexpected %u (0x%04x) != result %u (0x%04x) -> ok", "\"%s\". Unexpected %u (%04x) == result %u (0x%04x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_U16) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_u16[idx][1],
         type->header.desc.fn_name,
         (unsigned int)type->expected, type->expected,
         (unsigned int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_u16[idx][0],
      type->header.desc.fn_name,
      (unsigned int)type->expected, type->expected,
      (unsigned int)type->result, type->result
   )
}

static void print_assert_s16(void *ctx, void *vas)
{
   C_TEST_TYPE_S16 *type=(C_TEST_TYPE_S16 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_s16[][2] = {
      {"\"%s\". Expected %d (0x%04x) == result %d (0x%04x) -> ok", "\"%s\". Expected %d (0x%04x), but found %d (0x%04x) -> fail"},
      {"\"%s\". Unexpected %d (0x%04x) != result %d (0x%04x) -> ok", "\"%s\". Unexpected %u (%04x) == result %d (0x%04x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_S16) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_s16[idx][1],
         type->header.desc.fn_name,
         (signed int)type->expected, type->expected&0xFFFF,
         (signed int)type->result, type->result&0xFFFF
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_s16[idx][0],
      type->header.desc.fn_name,
      (signed int)type->expected, type->expected&0xFFFF,
      (signed int)type->result, type->result&0xFFFF
   )
}

static void print_assert_u32(void *ctx, void *vas)
{
   C_TEST_TYPE_U32 *type=(C_TEST_TYPE_U32 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_u32[][2] = {
      {"\"%s\". Expected %u (0x%08x) == result %u (0x%08x) -> ok", "\"%s\". Expected %u (0x%08x), but found %u (0x%08x) -> fail"},
      {"\"%s\". Unexpected %u (0x%08x) != result %u (0x%08x) -> ok", "\"%s\". Unexpected %u (%08x) == result %u (0x%08x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_U32) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_u32[idx][1],
         type->header.desc.fn_name,
         (unsigned int)type->expected, type->expected,
         (unsigned int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_u32[idx][0],
      type->header.desc.fn_name,
      (unsigned int)type->expected, type->expected,
      (unsigned int)type->result, type->result
   )
}

static void print_assert_s32(void *ctx, void *vas)
{
   C_TEST_TYPE_S32 *type=(C_TEST_TYPE_S32 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_s32[][2] = {
      {"\"%s\". Expected %d (0x%08x) == result %d (0x%08x) -> ok", "\"%s\". Expected %d (0x%08x), but found %d (0x%08x) -> fail"},
      {"\"%s\". Unexpected %d (0x%08x) != result %d (0x%08x) -> ok", "\"%s\". Unexpected %d (%08x) == result %d (0x%08x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_S32) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_s32[idx][1],
         type->header.desc.fn_name,
         (signed int)type->expected, type->expected,
         (signed int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_s32[idx][0],
      type->header.desc.fn_name,
      (signed int)type->expected, type->expected,
      (signed int)type->result, type->result
   )
}

_Static_assert(sizeof(unsigned long long int)==sizeof(uint64_t), "Assert error. Unsingned long int must be equal 64 bit");
static void print_assert_u64(void *ctx, void *vas)
{
   C_TEST_TYPE_U64 *type=(C_TEST_TYPE_U64 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_u64[][2] = {
      {"\"%s\". Expected %lu (0x%016llx) == result %lu (0x%016llx) -> ok", "\"%s\". Expected %lu (0x%016llx), but found %lu (0x%016llx) -> fail"},
      {"\"%s\". Unexpected %lu (0x%016llx) != result %lu (0x%016llx) -> ok", "\"%s\". Unexpected %lu (%016llx) == result %lu (0x%016llx) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_U64) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_u64[idx][1],
         type->header.desc.fn_name,
         (unsigned long long int)type->expected, type->expected,
         (unsigned long long int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_u64[idx][0],
      type->header.desc.fn_name,
      (unsigned long long int)type->expected, type->expected,
      (unsigned long long int)type->result, type->result
   )
}

_Static_assert(sizeof(long long int)==sizeof(int64_t), "Assert error. Long int must be equal 64 bit");
static void print_assert_s64(void *ctx, void *vas)
{
   C_TEST_TYPE_S64 *type=(C_TEST_TYPE_S64 *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_s64[][2] = {
      {"\"%s\". Expected %ld (0x%016llx) == result %ld (0x%016llx) -> ok", "\"%s\". Expected %ld (0x%016llx), but found %ld (0x%016llx) -> fail"},
      {"\"%s\". Unexpected %ld (0x%016llx) != result %ld (0x%016llx) -> ok", "\"%s\". Unexpected %ld (%016llx) == result %ld (0x%016llx) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_S64) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      CALLBACK_ON_ERROR

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_s64[idx][1],
         type->header.desc.fn_name,
         (long long int)type->expected, type->expected,
         (long long int)type->result, type->result
      )

      abort_tests();
   }

   CALLBACK_ON_SUCCESS

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_s64[idx][0],
      type->header.desc.fn_name,
      (long long int)type->expected, type->expected,
      (long long int)type->result, type->result
   )
}

static void print_assert_fail(void *ctx, void *vas)
{
   // TODO
   int p_sz;
   char *p;
   C_TEST_TYPE_FAIL *type=(C_TEST_TYPE_FAIL *)ctx;

   PRINT_CALLBACK
   SHOW_USER_NOTIFICATION
   CALLBACK_ON_ERROR

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
      ERROR_MSG_FMT("%.*s", p_sz, p)

   ERROR_MSG_FMT("\"%s\". Fail",
      type->header.desc.fn_name
   )

   free_vargs(vas);
   abort_tests();
}

static void add_test(void *ctx, void *vas)
{
   int err;
   void *p;
   size_t sz_tmp;

   if (_c_test_ptr) {

      sz_tmp=(((C_TEST_HEADER *)_c_test_ptr)->tests)*sizeof(C_TEST_FN)+sizeof(C_TEST_HEADER);

      if (!(p=realloc(_c_test_ptr, sz_tmp+sizeof(C_TEST_FN)))) {
         printf("\nFatal: Error when realloc test pointer @ %p\n", _c_test_ptr);
         free(_c_test_ptr);
         if ((err=free_vargs(vas)))
            ERROR_MSG_FMT("free_vargs @ add_test on memory reallocation error = %d at pointer (%p)", err, vas) 
         exit(1);
      }

      goto add_test_EXIT1;
   }

   if (!(p=malloc((sz_tmp=sizeof(C_TEST_HEADER))+sizeof(C_TEST_FN)))) {
      printf("\nFatal: Error when initialize pointer @ NULL");
      if ((err=free_vargs(vas)))
         ERROR_MSG_FMT("free_vargs @ add_test on memory allocation for creating header error = %d at pointer (%p)", err, vas) 
      exit(1);
   }

   TITLE_MSG("Begin adding test ...")

   C_TEST_INITIAL_ADD
   C_TEST_INITIAL_ADD_FN_ALL_NULL

add_test_EXIT1:
   memcpy((_c_test_ptr=p)+sz_tmp, ctx, ((C_TEST_TYPE_HEADER *)ctx)->desc.blk_size);
   TITLE_MSG_FMT("Adding test instance \"%s\" (%d)", ((C_TEST_FN_DESCRIPTION *)ctx)->fn_name, ++((C_TEST_HEADER *)p)->tests)

   if (((C_TEST_HEADER *)p)->on_add_test_fn)
      ((C_TEST_HEADER *)p)->on_add_test_fn(ctx);
}

#define ASSERT_PRELOAD \
   type.expected=expected;\
   type.result=result;

#define TEST_BEGIN \
   add_test((void *)&type, vas); \
   begin_test(vas);

static void assert_equal_bool(
   int expected,
   int result,
   void *vas
)
{
   static C_TEST_TYPE_BOOL type;

   (expected==C_TEST_TRUE)?(type.header.desc=C_TEST_FN_DESCRIPTION_ASSERT_TRUE):(type.header.desc=C_TEST_FN_DESCRIPTION_ASSERT_FALSE);
   ASSERT_PRELOAD
   TEST_BEGIN
}

#define CHECK_BOOL(fn_name) \
   if ((value!=C_TEST_FALSE)&&(value!=C_TEST_TRUE)) {\
      ERROR_MSG_FMT("Wrong value %d in %s. Was expected C_TEST_FALSE or C_TEST_TRUE but found %d (0x%08x)", value, fn_name, value, value)\
      abort_tests();\
   }

// BEGIN WARN: To be only used in asserts function only
//in arguments
//out: vas
#define VERIFY_VAS_SIG_VALID (uint64_t)0x0000000167abdd72
#define INVALID_ARGS_PARMS_MSG "\"%s\". Error %d: Invalid arguments parameters"
int assert_warning_util(void **vas, void *p, const char *FN_MACRO_NAME)
{
   int err;
   uint64_t sig;

   *vas=NULL;
   if (!p) {
      ERROR_MSG_FMT("Error. Null parameter. Try %s", FN_MACRO_NAME)
      return -100;
   }

   if (p==VAS_END_SIGNATURE) {
      if (((sig=*((uint64_t *)p))!=VERIFY_VAS_SIG_VALID)) {
         ERROR_MSG_FMT("Wrong message in %s signature @ (%p) with value (0x%016x)", FN_MACRO_NAME, p, (unsigned long long int)sig)
         return -101;
      }
      return 0;
   }

   if ((err=load_test_vargs(vas, p, NULL, VAS_END_SIGNATURE)))
      ERROR_MSG_FMT(INVALID_ARGS_PARMS_MSG, FN_MACRO_NAME, err)

   return err;

}
// END WARN

void assert_false(int value, ...)
{
   void *vas;
   va_list va;

   CHECK_BOOL("assert_false")
   va_start(va, value);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_FALSE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_equal_bool(C_TEST_FALSE, value, vas);
}

void assert_true(int value, ...)
{
   void *vas;
   va_list va;

   CHECK_BOOL("assert_true")
   va_start(va, value);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_TRUE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_equal_bool(C_TEST_TRUE, value, vas);
}

static void assert_int(int expected, int result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_INT type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_int(int expected, int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_int(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_INT, vas);
}

void assert_not_equal_int(int expected, int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_int(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_INT, vas);
}

static void assert_longint(long long int expected, long long int result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_LONG_INT type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_longint(long long int expected, long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_LONG_INT, vas);
}

void assert_not_equal_longint(long long int expected, long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_LONG_INT, vas);
}

static void assert_unsigned_longint(unsigned long long int expected, unsigned long long int result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_UNSIGNED_LONG_INT type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_unsigned_longint(unsigned long long int expected, unsigned long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_UNSIGNED_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_unsigned_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_UNSIGNED_LONG_INT, vas);
}

void assert_not_equal_unsigned_longint(unsigned long long int expected, unsigned long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_UNSIGNED_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_unsigned_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_UNSIGNED_LONG_INT, vas);
}

static void assert_double(double expected, double result, double delta, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_DOUBLE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   type.delta=delta;
   TEST_BEGIN
}

void assert_equal_double(double expected, double result, double delta, ...)
{
   void *vas;
   va_list va;

   va_start(va, delta);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_DOUBLE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_double(expected, result, delta, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_DOUBLE, vas);
}

void assert_not_equal_double(double expected, double result, double delta, ...)
{
   void *vas;
   va_list va;

   va_start(va, delta);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_DOUBLE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_double(expected, result, delta, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_DOUBLE, vas);
}

static void assert_byte(
   void *expected,
   void *result,
   size_t size,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_BYTE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   type.size=size;
   TEST_BEGIN
}

void assert_equal_byte(
   void *expected,
   void *result,
   size_t size,
   ...
)
{
   void *vas;
   va_list va;

   va_start(va, size);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_BYTE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_byte(expected, result, size, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_BYTE, vas);
}

void assert_not_equal_byte(
   void *expected,
   void *result,
   size_t size,
   ...
)
{
   void *vas;
   va_list va;

   va_start(va, size);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_BYTE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_byte(expected, result, size, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_BYTE, vas);
}

static void assert_string(
   const char *expected,
   const char *result,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_STRING type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN

}

void assert_equal_string(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_STRING")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING, vas);
}

void assert_not_equal_string(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_STRING")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING, vas);
}

void assert_equal_string_ignore_case(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_STRING_IGNORE_CASE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING_IGNORE_CASE, vas);
}

void assert_not_equal_string_ignore_case(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING_IGNORE_CASE, vas);
}

static void assert_nullable(
   void *result,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_NULLABLE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   type.pointer=result;
   TEST_BEGIN
}

void assert_null(void *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NULL")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_nullable(result, &C_TEST_FN_DESCRIPTION_ASSERT_NULL, vas);
}

void assert_not_null(void *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_NULL")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_nullable(result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_NULL, vas);
}

static void assert_u8(uint8_t expected, uint8_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_U8 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_u8(uint8_t expected, uint8_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_U8")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u8(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_U8, vas);
}

void assert_not_equal_u8(uint8_t expected, uint8_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_U8")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u8(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U8, vas);
}

static void assert_s8(int8_t expected, int8_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_S8 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_s8(int8_t expected, int8_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_S8")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s8(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_S8, vas);
}

void assert_not_equal_s8(int8_t expected, int8_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_S8")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s8(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S8, vas);
}

static void assert_u16(uint16_t expected, uint16_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_U16 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_u16(uint16_t expected, uint16_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_U16")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u16(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_U16, vas);
}

void assert_not_equal_u16(uint16_t expected, uint16_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_U16")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u16(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U16, vas);
}

static void assert_s16(int16_t expected, int16_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_S16 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_s16(int16_t expected, int16_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_S16")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s16(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_S16, vas);
}

void assert_not_equal_s16(int16_t expected, int16_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_S16")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s16(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S16, vas);
}

static void assert_u32(uint32_t expected, uint32_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_U32 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_u32(uint32_t expected, uint32_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_U32")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u32(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_U32, vas);
}

void assert_not_equal_u32(uint32_t expected, uint32_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_U32")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u32(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U32, vas);
}

static void assert_s32(int32_t expected, int32_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_S32 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_s32(int32_t expected, int32_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_S32")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s32(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_S32, vas);
}

void assert_not_equal_s32(int32_t expected, int32_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_S32")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s32(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S32, vas);
}

static void assert_u64(uint64_t expected, uint64_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_U64 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_u64(uint64_t expected, uint64_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_U64")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u64(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_U64, vas);
}

void assert_not_equal_u64(uint64_t expected, uint64_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_U64")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_u64(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_U64, vas);
}

static void assert_s64(int64_t expected, int64_t result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_S64 type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_s64(int64_t expected, int64_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_S64")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s64(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_S64, vas);
}

void assert_not_equal_s64(int64_t expected, int64_t result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_S64")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_s64(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_S64, vas);
}

//TODO
void assert_fail(void *result, ...)
{
   static C_TEST_TYPE_FAIL type;
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_FAIL")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   memcpy(&type.header.desc, &C_TEST_FN_DESCRIPTION_ASSERT_FAIL, sizeof(type.header.desc));
   type.pointer=result;
   TEST_BEGIN
}

uint64_t *get_va_end_signature()
{
   static uint64_t va_end_signature_u64=0x00000000df3f6198;
   return &va_end_signature_u64;
}

uint64_t *get_vas_end_signature()
{
   static uint64_t vas_end_signature_u64=0x0000000167abdd72;
   return &vas_end_signature_u64;
}

#ifdef DEBUG_TEST
 inline int load_test_vargs_for_test(void **vargs, ...)
 {
    void *ctx;
    va_list va;
    va_start(va, vargs);
    ctx=(void *)va_arg(va, void *);
    va_end(va);

    return load_test_vargs(vargs, ctx, NULL, VAS_END_SIGNATURE);
 }

 inline int free_vargs_for_test(void *vargs)
 {
    return free_vargs(vargs);
 }

 static char *ctest_setter_has_util(void *ctest_setter, uint32_t sig)
 {
    C_TEST_VARGS_MSG *res;

    if (!ctest_setter)
       return NULL;

    if ((res=check_vargs_sigmsg_exists(((C_TEST_VARGS_MSG_HEADER *)ctest_setter)->vargs_msgs, sig)))
      return res->msg;

    return NULL;
 }

 inline char *ctest_setter_has_title(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_TITLE);
 }

 inline char *ctest_setter_has_info(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_INFO);
 }

 inline char *ctest_setter_has_warn(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_WARNING);
 }

 inline char *ctest_setter_has_onerror(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_ERROR);
 }

 inline char *ctest_setter_has_onsuccess(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_SUCCESS);
 }

 void show_message_text()
 {
    const char *msg="This is a simple %s message";

     TITLE_MSG_FMT(msg, "TITLE")
     ERROR_MSG_FMT(msg, "ERROR")
     SUCCESS_MSG_FMT(msg, "SUCCESS")
     WARN_MSG_FMT(msg, "WARNING")
     INFO_MSG_FMT(msg, "INFO")
 }

#endif

