#include "Enclave.h"
#include "Enclave_t.h"
#include "sgx_tseal.h"
#include <algorithm>
#include <mbusafecrt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef size_t sys_word_t;

typedef struct _thread_data_t {
  sys_word_t self_addr;
  sys_word_t last_sp;          /* set by urts, relative to TCS */
  sys_word_t stack_base_addr;  /* set by urts, relative to TCS */
  sys_word_t stack_limit_addr; /* set by urts, relative to TCS */
  sys_word_t first_ssa_gpr;    /* set by urts, relative to TCS */
  sys_word_t
      stack_guard; /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

  sys_word_t flags;
  sys_word_t xsave_size; /* in bytes (se_ptrace.c needs to know its offset).*/
  sys_word_t last_error; /* init to be 0. Used by trts. */
  struct _thread_data_t *m_next;
  sys_word_t tls_addr;  /* points to TLS pages */
  sys_word_t tls_array; /* points to TD.tls_addr relative to TCS */
  intptr_t exception_flag;
  sys_word_t cxx_thread_info[6];
  sys_word_t stack_commit_addr;
} thread_data_t;

extern uint64_t g_enclave_base, g_enclave_size;

extern "C" thread_data_t *get_thread_data(void);

uint64_t global_addr;

int g_oob_arr[4];

void ecall_get_ssa_addr(void **ssa) {
  // detect global oob
  // g_oob_arr[4] = 1;

  // detect stack oob
  // int stack_arr[4] = {0};
  // int a = stack_arr[4];
  // (void)a;

  // detect heap oob
  // int *heap_arr = (int *)malloc(4 * sizeof(int));
  // int b = heap_arr[4];
  // (void)b;

  if (ssa == nullptr)
    return;
  global_addr = (uint64_t)ssa;
  thread_data_t *td = get_thread_data();
  *ssa = (void *)td;
  // *(ssa - 10) = (void *)td;
  // *ssa = (void *)((uint64_t)td - (18 << 12));

  // test null and elrange guard page
  // int *invalid_ptr = nullptr;
  // int *invalid_ptr = (int *)((uint64_t)g_enclave_base - 0x1000);
  // int *invalid_ptr = (int *)((uint64_t)g_enclave_base - 1);
  // int *invalid_ptr = (int *)((uint64_t)g_enclave_base + g_enclave_size - 1);
  // int *invalid_ptr = (int *)((uint64_t)g_enclave_base + g_enclave_size + 1);
  // int bad_dereference = *invalid_ptr;
  // (void)bad_dereference;
  int *ret_test;
  int *test = nullptr;
  int **ptr_test = &test;
  ocall_test(&ret_test, ptr_test);
}

void ecall_use_ssa_addr(void *ssa) {
  if (global_addr) {
    int val = *(int *)(global_addr + 1);
    (void)val;
  }
  (void)ssa;
}

void ecall_use_array(int arr[5][6][7]) {
  int a = arr[2][3][4];
  (void)a;
  // int b = arr[5][6];
  // (void)b;
}

extern "C" void *memcpy(void *dest, const void *src, size_t count);
extern "C" void print_shadow(void *ptr);

#define SGXSAN_SENSITIVE __attribute__((annotate("SGXSAN_SENSITIVE")))

SGXSAN_SENSITIVE char g_c = '9';
SGXSAN_SENSITIVE char *g_ptr;
SGXSAN_SENSITIVE const char *g_str = "sensitive";
SGXSAN_SENSITIVE static int g_arr[5] = {0x61, 0x62, 0x63, 0x64, 0x65};

struct struct_type {
  double a;
  SGXSAN_SENSITIVE char b;
};

char deepCall(char c) { return c; }

char (*func)(char c);
char indirectCall(char c) {
  char indirectCall_c = c;
  printf("%c\n", indirectCall_c);
  return deepCall(indirectCall_c);
}

char (*func_ret)();
char return_sensitive() {
  SGXSAN_SENSITIVE char sensitive = 'c';
  return sensitive;
}

char test1() {
  struct_type ty;
  ty.b = '1';
  char ty_b_cp = ty.b;
  func = indirectCall;
  return func(ty_b_cp);
}

char test2() {
  SGXSAN_SENSITIVE int *malloc_ptr = (int *)malloc(sizeof(int) * 100);
  malloc_ptr[0] = 0x32;
  malloc_ptr[1] = 0x32;
  func = indirectCall;
  char ret = func((char)malloc_ptr[1]);
  free(malloc_ptr);
  return ret;
}

char test3() {
  SGXSAN_SENSITIVE char test1_a = '3';
  SGXSAN_SENSITIVE char *p_a = &test1_a;
  char a_cp = *p_a;
  func = indirectCall;
  return func(a_cp);
}

char test4() {
  func_ret = return_sensitive;
  return func_ret();
}

char test5() {
  func_ret = return_sensitive;
  func = indirectCall;
  return func(func_ret());
}

char test6() {
  SGXSAN_SENSITIVE int *malloc_ptr = (int *)malloc(sizeof(int) * 100);
  malloc_ptr[0] = 0x36;
  char c;
  char *c_alias = (char *)memcpy(&c, malloc_ptr, 1);
  char ret = indirectCall(*c_alias);
  ret = indirectCall(c);
  free(malloc_ptr);
  return ret;
}

char test7() {
  char unsealed_data[BUFSIZ] = "Data to encrypt";
  uint32_t sealed_data_size =
      sgx_calc_sealed_data_size(0, (uint32_t)strlen(unsealed_data));
  sgx_sealed_data_t *sealed_buf = (sgx_sealed_data_t *)malloc(sealed_data_size);
  sgx_seal_data(0, nullptr, (uint32_t)strlen(unsealed_data),
                (uint8_t *)unsealed_data, sealed_data_size, sealed_buf);
  return unsealed_data[0];
}

char test8() {
  SGXSAN_SENSITIVE char a = '8';
  char *p_a = &a;
  char *p_b = p_a;
  char a_cp = *p_b;
  return a_cp;
}

char test9() {
  func = indirectCall;
  return func(g_c);
}

char test10() {
  char *p_gc = &g_c;
  char *p_b = p_gc;
  char gc_cp = *p_b;
  return gc_cp;
}

char test11() {
  func = indirectCall;
  return func((char)g_arr[1]);
}

char test12() {
  struct_type test12_ty;
  test12_ty.b = 'c';
  char tmp[7];
  tmp[5] = test12_ty.b;
  func = indirectCall;
  return func(tmp[5]);
}

void *(*calloc_ptr)(size_t num, size_t size) = calloc;

void *(*func_ptr)(size_t size);
void *malloc_wrapper(size_t size) {
  void *ptr = calloc_ptr(1, size);
  return ptr;
}

__attribute__((noinline)) void *wolfSSL_Malloc(size_t size) {
  return malloc(size);
}

__attribute__((noinline)) void encrypt_secret(char *src, char *dst,
                                              size_t len) {
  for (size_t i = 0; i < len; i++) {
    dst[i] = src[i] + 1;
  }
}

char test13() {
  size_t len = 100;
  char *srcHeap = (char *)wolfSSL_Malloc(len);
  if (srcHeap[0] == 0)
    srcHeap[0] = 'd';
  func_ptr = malloc_wrapper;
  char *dstHeap = (char *)func_ptr(len);
  encrypt_secret(srcHeap, dstHeap, len);
  return srcHeap[0];
}

void ecall_test_sensitive_leak_san(char leak[15]) {
  char test1_ret = test1();
  (void)test1_ret;
  char test2_ret = test2();
  (void)test2_ret;
  char test3_ret = test3();
  (void)test3_ret;
  char test4_ret = test4();
  (void)test4_ret;
  char test5_ret = test5();
  (void)test5_ret;
  char test6_ret = test6();
  (void)test6_ret;
  char test7_ret = test7();
  (void)test7_ret;
  char test8_ret = test8();
  (void)test8_ret;
  char test9_ret = test9();
  (void)test9_ret;
  char test10_ret = test10();
  (void)test10_ret;
  char test11_ret = test11();
  (void)test11_ret;
  char test12_ret = test12();
  (void)test12_ret;
  char test13_ret = test13();
  (void)test13_ret;

  for (int i = 0; i < 15; i++) {
    // print_shadow(&leak[i]);
    leak[i] = test12_ret;
  }
}
