/*
 * StringHookTests.cpp - Comprehensive tests for all 32 __sgxsan_ hook functions
 *
 * Tests coverage:
 * - Safe memory operations (3): memcpy_s, memset_s, memmove_s
 * - Known-size operations (12): memcmp, memchr, strncpy, strlcpy, snprintf,
 * vsnprintf, strncmp, strnlen, strncat, bzero, bcopy, mempcpy
 * - Safe (_s) functions (6): strcpy_s, strncpy_s, strcat_s, strncat_s,
 * sprintf_s, _snprintf_s
 * - NUL-terminated functions (8): strlen, strcmp, strchr, strrchr, strstr,
 * strspn, strcspn, strpbrk
 * - BSD/POSIX functions (3): stpncpy, strndup, bcmp
 *
 * Note: strcpy, strcat, stpcpy, strdup are deprecated in SGX tlibc and not
 * hooked
 */

#include "../Enclave.h"
#include "Enclave_t.h"
#include <mbusafecrt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg)                                                 \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("[FAIL] %s: %s\n", __func__, msg);                                \
      return false;                                                            \
    }                                                                          \
  } while (0)

#define TEST_PASS()                                                            \
  do {                                                                         \
    printf("[PASS] %s\n", __func__);                                           \
    return true;                                                               \
  } while (0)

// ============================================================================
// Category 1: Safe Memory Operations (3 functions)
// ============================================================================

static bool test_memcpy_s() {
  char src[10] = "hello";
  char dst[10] = {0};
  errno_t ret = memcpy_s(dst, sizeof(dst), src, 6);
  TEST_ASSERT(ret == 0, "memcpy_s failed");
  TEST_ASSERT(strcmp(dst, "hello") == 0, "memcpy_s content mismatch");
  TEST_PASS();
}

static bool test_memset_s() {
  char buf[10] = "hello";
  errno_t ret = memset_s(buf, sizeof(buf), 'A', 5);
  TEST_ASSERT(ret == 0, "memset_s failed");
  TEST_ASSERT(memcmp(buf, "AAAAA", 5) == 0, "memset_s content mismatch");
  TEST_PASS();
}

static bool test_memmove_s() {
  char buf[20] = "hello world";
  // Test overlapping move
  int ret = memmove_s(buf + 6, 14, buf, 11);
  TEST_ASSERT(ret == 0, "memmove_s failed");
  TEST_ASSERT(strcmp(buf + 6, "hello world") == 0,
              "memmove_s content mismatch");
  TEST_PASS();
}

// ============================================================================
// Category 2: Known-size Operations (12 functions)
// ============================================================================

static bool test_memcmp() {
  char s1[10] = "hello";
  char s2[10] = "hello";
  char s3[10] = "world";
  TEST_ASSERT(memcmp(s1, s2, 5) == 0, "memcmp equal failed");
  TEST_ASSERT(memcmp(s1, s3, 5) != 0, "memcmp not-equal failed");
  TEST_PASS();
}

static bool test_memchr() {
  char s[10] = "hello";
  void *p = memchr(s, 'l', 5);
  TEST_ASSERT(p == (s + 2), "memchr found wrong position");
  p = memchr(s, 'z', 5);
  TEST_ASSERT(p == NULL, "memchr should return NULL");
  TEST_PASS();
}

static bool test_strncpy() {
  char dst[10] = {0};
  char src[10] = "hello";
  char *ret = strncpy(dst, src, 10);
  TEST_ASSERT(ret == dst, "strncpy return value wrong");
  TEST_ASSERT(strcmp(dst, "hello") == 0, "strncpy content mismatch");
  TEST_PASS();
}

static bool test_strlcpy() {
  char dst[10] = {0};
  char src[20] = "hello world";
  size_t ret = strlcpy(dst, src, 10);
  TEST_ASSERT(ret == 11, "strlcpy return value wrong"); // Returns strlen(src)
  TEST_ASSERT(strcmp(dst, "hello wor") == 0, "strlcpy content mismatch");
  TEST_PASS();
}

static bool test_snprintf() {
  char buf[20] = {0};
  int ret = snprintf(buf, sizeof(buf), "num=%d str=%s", 42, "test");
  TEST_ASSERT(ret > 0, "snprintf failed");
  TEST_ASSERT(strcmp(buf, "num=42 str=test") == 0, "snprintf content mismatch");
  TEST_PASS();
}

static bool test_vsnprintf_wrapper(const char *fmt, ...) {
  char buf[20] = {0};
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  TEST_ASSERT(ret > 0, "vsnprintf failed");
  TEST_ASSERT(strcmp(buf, "test 123") == 0, "vsnprintf content mismatch");
  return true;
}

static bool test_vsnprintf() {
  bool ret = test_vsnprintf_wrapper("%s %d", "test", 123);
  TEST_ASSERT(ret, "vsnprintf wrapper failed");
  TEST_PASS();
}

static bool test_strncmp() {
  TEST_ASSERT(strncmp("hello", "hello", 5) == 0, "strncmp equal failed");
  TEST_ASSERT(strncmp("hello", "world", 5) != 0, "strncmp not-equal failed");
  TEST_ASSERT(strncmp("hello", "helium", 3) == 0,
              "strncmp partial match failed");
  TEST_PASS();
}

static bool test_strnlen() {
  char s[10] = "hello";
  TEST_ASSERT(strnlen(s, 10) == 5, "strnlen wrong length");
  TEST_ASSERT(strnlen(s, 3) == 3, "strnlen with max < strlen failed");
  TEST_PASS();
}

static bool test_strncat() {
  char dst[20] = "hello";
  char src[10] = " world";
  char *ret = strncat(dst, src, 6);
  TEST_ASSERT(ret == dst, "strncat return value wrong");
  TEST_ASSERT(strcmp(dst, "hello world") == 0, "strncat content mismatch");
  TEST_PASS();
}

static bool test_bzero() {
  char buf[10] = "hello";
  bzero(buf, 5);
  TEST_ASSERT(memcmp(buf, "\0\0\0\0\0", 5) == 0, "bzero failed");
  TEST_PASS();
}

static bool test_bcopy() {
  char src[10] = "hello";
  char dst[10] = {0};
  bcopy(src, dst, 6);
  TEST_ASSERT(strcmp(dst, "hello") == 0, "bcopy content mismatch");
  TEST_PASS();
}

static bool test_mempcpy() {
  char src[10] = "hello";
  char dst[10] = {0};
  void *ret = mempcpy(dst, src, 5);
  TEST_ASSERT(ret == (dst + 5), "mempcpy return pointer wrong");
  TEST_ASSERT(memcmp(dst, "hello", 5) == 0, "mempcpy content mismatch");
  TEST_PASS();
}

// ============================================================================
// Category 3: Safe (_s) Functions (6 functions)
// ============================================================================

static bool test_strcpy_s() {
  char dst[10] = {0};
  char src[10] = "hello";
  errno_t ret = strcpy_s(dst, sizeof(dst), src);
  TEST_ASSERT(ret == 0, "strcpy_s failed");
  TEST_ASSERT(strcmp(dst, "hello") == 0, "strcpy_s content mismatch");
  TEST_PASS();
}

static bool test_strncpy_s() {
  char dst[10] = {0};
  char src[10] = "hello";
  errno_t ret = strncpy_s(dst, sizeof(dst), src, 5);
  TEST_ASSERT(ret == 0, "strncpy_s failed");
  TEST_ASSERT(strcmp(dst, "hello") == 0, "strncpy_s content mismatch");
  TEST_PASS();
}

static bool test_strcat_s() {
  char dst[20] = "hello";
  char src[10] = " world";
  errno_t ret = strcat_s(dst, sizeof(dst), src);
  TEST_ASSERT(ret == 0, "strcat_s failed");
  TEST_ASSERT(strcmp(dst, "hello world") == 0, "strcat_s content mismatch");
  TEST_PASS();
}

static bool test_strncat_s() {
  char dst[20] = "hello";
  char src[10] = " world";
  errno_t ret = strncat_s(dst, sizeof(dst), src, 6);
  TEST_ASSERT(ret == 0, "strncat_s failed");
  TEST_ASSERT(strcmp(dst, "hello world") == 0, "strncat_s content mismatch");
  TEST_PASS();
}

static bool test_sprintf_s() {
  char buf[30] = {0};
  int ret = sprintf_s(buf, sizeof(buf), "value=%d", 42);
  TEST_ASSERT(ret > 0, "sprintf_s failed");
  TEST_ASSERT(strcmp(buf, "value=42") == 0, "sprintf_s content mismatch");
  TEST_PASS();
}

static bool test_snprintf_s() {
  char buf[30] = {0};
  // SGX's _snprintf_s: _snprintf_s(buf, sizeInBytes, count, fmt, ...)
  int ret = _snprintf_s(buf, sizeof(buf), 20, "test %d", 123);
  TEST_ASSERT(ret > 0, "snprintf_s failed");
  TEST_ASSERT(strcmp(buf, "test 123") == 0, "snprintf_s content mismatch");
  TEST_PASS();
}

// ============================================================================
// Category 4: NUL-terminated Functions (8 functions)
// ============================================================================

static bool test_strlen() {
  char s[10] = "hello";
  TEST_ASSERT(strlen(s) == 5, "strlen wrong length");
  TEST_ASSERT(strlen("") == 0, "strlen empty string failed");
  TEST_PASS();
}

static bool test_strcmp() {
  TEST_ASSERT(strcmp("hello", "hello") == 0, "strcmp equal failed");
  TEST_ASSERT(strcmp("abc", "xyz") < 0, "strcmp less-than failed");
  TEST_ASSERT(strcmp("xyz", "abc") > 0, "strcmp greater-than failed");
  TEST_PASS();
}

static bool test_strchr() {
  char s[10] = "hello";
  char *p = strchr(s, 'l');
  TEST_ASSERT(p == (s + 2), "strchr found wrong position");
  p = strchr(s, 'z');
  TEST_ASSERT(p == NULL, "strchr should return NULL");
  TEST_PASS();
}

static bool test_strrchr() {
  char s[10] = "hello";
  char *p = strrchr(s, 'l');
  TEST_ASSERT(p == (s + 3), "strrchr found wrong position");
  p = strrchr(s, 'z');
  TEST_ASSERT(p == NULL, "strrchr should return NULL");
  TEST_PASS();
}

static bool test_strstr() {
  char s[20] = "hello world";
  char *p = strstr(s, "world");
  TEST_ASSERT(p == (s + 6), "strstr found wrong position");
  p = strstr(s, "xyz");
  TEST_ASSERT(p == NULL, "strstr should return NULL");
  TEST_PASS();
}

static bool test_strspn() {
  char s[10] = "hello";
  size_t n = strspn(s, "helo");
  TEST_ASSERT(n == 5,
              "strspn wrong count"); // All chars in "hello" are in "helo"
  n = strspn(s, "abc");
  TEST_ASSERT(n == 0, "strspn should return 0");
  TEST_PASS();
}

static bool test_strcspn() {
  char s[10] = "hello";
  size_t n = strcspn(s, "aeiou");
  TEST_ASSERT(n == 1,
              "strcspn wrong count"); // 'e' is the first vowel at position 1
  n = strcspn(s, "xyz");
  TEST_ASSERT(n == 5, "strcspn should return strlen");
  TEST_PASS();
}

static bool test_strpbrk() {
  char s[10] = "hello";
  char *p = strpbrk(s, "aeiou");
  TEST_ASSERT(p == (s + 1),
              "strpbrk found wrong position"); // 'e' at position 1
  p = strpbrk(s, "xyz");
  TEST_ASSERT(p == NULL, "strpbrk should return NULL");
  TEST_PASS();
}

// ============================================================================
// Category 5: Additional BSD/POSIX Functions (3 functions)
// Note: strcpy, strcat, stpcpy, strdup are deprecated in SGX and not hooked
// ============================================================================

static bool test_stpncpy() {
  char dst[10] = {0};
  char src[10] = "hello";
  char *ret = stpncpy(dst, src, 10);
  TEST_ASSERT(ret == (dst + 5),
              "stpncpy return pointer wrong"); // Points to first NUL written
  TEST_ASSERT(strcmp(dst, "hello") == 0, "stpncpy content mismatch");
  TEST_PASS();
}

static bool test_strndup() {
  char src[20] = "hello world";
  char *dup = strndup(src, 5);
  TEST_ASSERT(dup != NULL, "strndup returned NULL");
  TEST_ASSERT(strcmp(dup, "hello") == 0, "strndup content mismatch");
  TEST_ASSERT(strlen(dup) == 5, "strndup wrong length");
  free(dup);
  TEST_PASS();
}

static bool test_bcmp() {
  char s1[10] = "hello";
  char s2[10] = "hello";
  char s3[10] = "world";
  TEST_ASSERT(bcmp(s1, s2, 5) == 0, "bcmp equal failed");
  TEST_ASSERT(bcmp(s1, s3, 5) != 0, "bcmp not-equal failed");
  TEST_PASS();
}

// ============================================================================
// OOB Detection Tests
//
// Each function INTENTIONALLY triggers an out-of-bounds access.
// SGXSan MUST detect it and call abort() — this is the expected "pass" outcome.
// If the function returns normally, SGXSan FAILED to detect the violation.
//
// Design: a single ecall ecall_test_string_hooks_oob(int test_id) runs one
// test at a time.  The caller (host side) should observe
// SGX_ERROR_ENCLAVE_CRASHED on success and a clean return on failure.
// ============================================================================

typedef enum {
  OOB_ID_MEMCPY_STACK = 0,  // memcpy: count > dst stack buffer size (OOB write)
  OOB_ID_MEMSET_STACK = 1,  // memset: count > stack buffer size     (OOB write)
  OOB_ID_MEMCPY_HEAP = 2,   // memcpy: count > dst heap buffer size  (OOB write)
  OOB_ID_MEMSET_HEAP = 3,   // memset: count > heap buffer size      (OOB write)
  OOB_ID_STRNCPY_STACK = 4, // strncpy: n > dst stack buffer size    (OOB write)
  OOB_ID_MEMCMP_STACK = 5,  // memcmp:  n > stack buffer size        (OOB read)
  OOB_ID_MEMPCPY_HEAP = 6,  // mempcpy: count > dst heap buffer size (OOB write)
  OOB_ID_NULL_DEREF_READ = 7,   // NULL pointer dereference (read)
  OOB_ID_NULL_DEREF_WRITE = 8,  // NULL pointer dereference (write)
  OOB_ID_HEAP_OOB_READ = 9,     // heap direct OOB read (index past end)
  OOB_ID_HEAP_OOB_WRITE = 10,   // heap direct OOB write (index past end)
  OOB_ID_STACK_OOB_READ = 11,   // stack direct OOB read (index past end)
  OOB_ID_STACK_OOB_WRITE = 12,  // stack direct OOB write (index past end)
  OOB_ID_GLOBAL_OOB_READ = 13,  // global array OOB read
  OOB_ID_GLOBAL_OOB_WRITE = 14, // global array OOB write
  OOB_TEST_COUNT
} oob_test_id_t;

// Global sink prevents the compiler from optimizing away OOB side-effects.
static volatile int g_oob_sink = 0;

// Global array used for global-variable OOB tests (8 bytes).
static char g_global_buf[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};

static __attribute__((noinline)) void oob_memcpy_stack(void) {
  char src[10] = "hello!X";
  char dst[6] = {0};
  // OOB: copying 7 bytes into a 6-byte dst
  memcpy(dst, src, 7);
  g_oob_sink = dst[0];
}

static __attribute__((noinline)) void oob_memset_stack(void) {
  char buf[6] = {0};
  // OOB: setting 7 bytes in a 6-byte buffer
  memset(buf, 'A', 7);
  g_oob_sink = buf[0];
}

static __attribute__((noinline)) void oob_memcpy_heap(void) {
  char *dst = (char *)malloc(6);
  char src[10] = "hello!X";
  // OOB: copying 7 bytes into a 6-byte heap allocation
  memcpy(dst, src, 7);
  g_oob_sink = dst[0];
  free(dst);
}

static __attribute__((noinline)) void oob_memset_heap(void) {
  char *buf = (char *)malloc(6);
  // OOB: setting 7 bytes in a 6-byte heap allocation
  memset(buf, 'A', 7);
  g_oob_sink = buf[0];
  free(buf);
}

static __attribute__((noinline)) void oob_strncpy_stack(void) {
  char src[20] = "hello!X";
  char dst[6] = {0};
  // OOB: copying 7 bytes into a 6-byte dst
  strncpy(dst, src, 7);
  g_oob_sink = dst[0];
}

static __attribute__((noinline)) void oob_memcmp_stack(void) {
  char s1[6] = {'h', 'e', 'l', 'l', 'o', '!'};
  char s2[6] = {'w', 'o', 'r', 'l', 'd', '!'};
  // OOB: comparing 7 bytes from 6-byte buffers (OOB read on both)
  int result = memcmp(s1, s2, 7);
  g_oob_sink = result;
}

static __attribute__((noinline)) void oob_mempcpy_heap(void) {
  char *dst = (char *)malloc(6);
  char src[10] = "hello!X";
  // OOB: copying 7 bytes into a 6-byte heap allocation
  mempcpy(dst, src, 7);
  g_oob_sink = dst[0];
  free(dst);
}

// ---- NULL pointer dereference ----

static __attribute__((noinline)) void oob_null_deref_read(void) {
  // Dereference address 0 (read)
  volatile int *p = (volatile int *)0;
  g_oob_sink = *p;
}

static __attribute__((noinline)) void oob_null_deref_write(void) {
  // Dereference address 0 (write)
  volatile int *p = (volatile int *)0;
  *p = 42;
}

// ---- Heap direct OOB ----

static __attribute__((noinline)) void oob_heap_oob_read(void) {
  char *buf = (char *)malloc(8);
  // OOB read: access index 9 on an 8-byte allocation
  g_oob_sink = buf[9];
  free(buf);
}

static __attribute__((noinline)) void oob_heap_oob_write(void) {
  char *buf = (char *)malloc(7);
  // OOB write: access index 9 on an 8-byte allocation
  buf[7] = 'X';
  g_oob_sink = buf[0];
  free(buf);
}

// ---- Stack direct OOB ----

static __attribute__((noinline)) void oob_stack_oob_read(void) {
  char arr[6] = "hello";
  // OOB read: access index 9 on an 8-element stack array
  g_oob_sink = arr[7];
}

static __attribute__((noinline)) void oob_stack_oob_write(void) {
  char arr[6] = {0};
  // OOB write: access index 9 on an 8-element stack array
  arr[6] = 'X';
  g_oob_sink = arr[0];
}

// ---- Global variable OOB ----

static __attribute__((noinline)) void oob_global_oob_read(void) {
  // OOB read: access index 8 on g_global_buf[8]
  g_oob_sink = g_global_buf[8];
}

static __attribute__((noinline)) void oob_global_oob_write(void) {
  // OOB write: access index 9 on g_global_buf[8]
  g_global_buf[9] = 'X';
  g_oob_sink = g_global_buf[0];
}

typedef void (*oob_func_t)(void);

static const oob_func_t oob_tests[OOB_TEST_COUNT] = {
    oob_memcpy_stack,     //  0: OOB_ID_MEMCPY_STACK
    oob_memset_stack,     //  1: OOB_ID_MEMSET_STACK
    oob_memcpy_heap,      //  2: OOB_ID_MEMCPY_HEAP
    oob_memset_heap,      //  3: OOB_ID_MEMSET_HEAP
    oob_strncpy_stack,    //  4: OOB_ID_STRNCPY_STACK
    oob_memcmp_stack,     //  5: OOB_ID_MEMCMP_STACK
    oob_mempcpy_heap,     //  6: OOB_ID_MEMPCPY_HEAP
    oob_null_deref_read,  //  7: OOB_ID_NULL_DEREF_READ
    oob_null_deref_write, //  8: OOB_ID_NULL_DEREF_WRITE
    oob_heap_oob_read,    //  9: OOB_ID_HEAP_OOB_READ
    oob_heap_oob_write,   // 10: OOB_ID_HEAP_OOB_WRITE
    oob_stack_oob_read,   // 11: OOB_ID_STACK_OOB_READ
    oob_stack_oob_write,  // 12: OOB_ID_STACK_OOB_WRITE
    oob_global_oob_read,  // 13: OOB_ID_GLOBAL_OOB_READ
    oob_global_oob_write, // 14: OOB_ID_GLOBAL_OOB_WRITE
};

static const char *oob_test_names[OOB_TEST_COUNT] = {
    "memcpy        - stack dst OOB write  (n=7 into dst[6])",
    "memset        - stack buf OOB write  (n=7 into buf[6])",
    "memcpy        - heap  dst OOB write  (n=7 into malloc(6))",
    "memset        - heap  buf OOB write  (n=7 into malloc(6))",
    "strncpy       - stack dst OOB write  (n=7 into dst[6])",
    "memcmp        - stack     OOB read   (n=7 from s[6]/s[6])",
    "mempcpy       - heap  dst OOB write  (n=7 into malloc(6))",
    "NULL deref    - read  from address 0",
    "NULL deref    - write to  address 0",
    "heap direct   - OOB read  (buf[9] on malloc(8))",
    "heap direct   - OOB write (buf[9] on malloc(8))",
    "stack direct  - OOB read  (arr[9] on arr[8])",
    "stack direct  - OOB write (arr[9] on arr[8])",
    "global direct - OOB read  (g_global_buf[9] on [8])",
    "global direct - OOB write (g_global_buf[9] on [8])",
};

/*
 * ecall_test_string_hooks_oob - Run one OOB negative test by ID.
 *
 * Expected outcome:  SGXSan detects the violation → abort() → enclave crashes
 *                    → host sees SGX_ERROR_ENCLAVE_CRASHED  → TEST PASSED
 * Failure indicator: function returns normally (no abort)  → TEST FAILED
 */
void ecall_test_string_hooks_oob(int test_id) {
  test_id = ((test_id % OOB_TEST_COUNT) + OOB_TEST_COUNT) % OOB_TEST_COUNT;

  printf("\n[OOB Test] #%d: %s\n", test_id, oob_test_names[test_id]);
  printf("[OOB Test] Triggering OOB — SGXSan SHOULD detect and abort...\n");

  oob_tests[test_id]();

  /* Reaching here means SGXSan did NOT detect the OOB — detection failure. */
  printf("[OOB Test] *** DETECTION FAILURE: SGXSan did NOT abort for test #%d "
         "(%s) ***\n",
         test_id, oob_test_names[test_id]);
}

// ============================================================================
// Main Test Runner
// ============================================================================

typedef bool (*test_func_t)(void);

typedef struct {
  const char *category;
  const char *name;
  test_func_t func;
} test_case_t;

#define TEST_CASE(cat, func) {cat, #func, test_##func}

static const test_case_t all_tests[] = {
    // Safe memory operations
    TEST_CASE("SafeMem", memcpy_s),
    TEST_CASE("SafeMem", memset_s),
    TEST_CASE("SafeMem", memmove_s),

    // Known-size operations
    TEST_CASE("KnownSize", memcmp),
    TEST_CASE("KnownSize", memchr),
    TEST_CASE("KnownSize", strncpy),
    TEST_CASE("KnownSize", strlcpy),
    TEST_CASE("KnownSize", snprintf),
    TEST_CASE("KnownSize", vsnprintf),
    TEST_CASE("KnownSize", strncmp),
    TEST_CASE("KnownSize", strnlen),
    TEST_CASE("KnownSize", strncat),
    TEST_CASE("KnownSize", bzero),
    TEST_CASE("KnownSize", bcopy),
    TEST_CASE("KnownSize", mempcpy),

    // Safe (_s) functions
    TEST_CASE("Safe_s", strcpy_s),
    TEST_CASE("Safe_s", strncpy_s),
    TEST_CASE("Safe_s", strcat_s),
    TEST_CASE("Safe_s", strncat_s),
    TEST_CASE("Safe_s", sprintf_s),
    TEST_CASE("Safe_s", snprintf_s),

    // NUL-terminated functions
    TEST_CASE("NULTerm", strlen),
    TEST_CASE("NULTerm", strcmp),
    TEST_CASE("NULTerm", strchr),
    TEST_CASE("NULTerm", strrchr),
    TEST_CASE("NULTerm", strstr),
    TEST_CASE("NULTerm", strspn),
    TEST_CASE("NULTerm", strcspn),
    TEST_CASE("NULTerm", strpbrk),

    // BSD/POSIX functions (strcpy, strcat, stpcpy, strdup not available in SGX)
    TEST_CASE("BSD_POSIX", stpncpy),
    TEST_CASE("BSD_POSIX", strndup),
    TEST_CASE("BSD_POSIX", bcmp),
};

void ecall_test_string_hooks(void) {
  printf("\n========================================\n");
  printf("  String Hook Tests (32 functions)\n");
  printf("========================================\n\n");

  int total = sizeof(all_tests) / sizeof(all_tests[0]);
  int passed = 0;
  int failed = 0;
  const char *current_category = "";

  for (int i = 0; i < total; i++) {
    const test_case_t *test = &all_tests[i];

    // Print category header
    if (strcmp(current_category, test->category) != 0) {
      current_category = test->category;
      printf("\n--- Category: %s ---\n", current_category);
    }

    // Run test
    bool result = test->func();
    if (result) {
      passed++;
    } else {
      failed++;
    }
  }

  printf("\n========================================\n");
  printf("  Test Summary\n");
  printf("========================================\n");
  printf("Total:  %d\n", total);
  printf("Passed: %d\n", passed);
  printf("Failed: %d\n", failed);
  printf("========================================\n\n");
}
