/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)
 *
 * Generated from EDL: Enclave.edl
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Register harnesses, calculate weights
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 _harness_xxx()   ← Auto-generated test functions
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * EDL Attribute Reference
 * ============================================================================
 *
 * | Attribute    | Meaning             | Fuzzing Strategy (ECall)         |
 * |--------------|---------------------|----------------------------------|
 * | [in]         | Input to callee     | Generate fuzzy data (Host→Encl)  |
 * | [out]        | Output from callee  | Allocate buffer (Encl→Host)      |
 * | [in,out]     | Bidirectional       | Generate input + allocate        |
 * | [size=N]     | Buffer size (bytes) | Use N for allocation             |
 * | [count=N]    | Array element count | Use N * sizeof(element)          |
 * | [string]     | Null-terminated str | Ensure null terminator           |
 * | [user_check] | No auto checking    | High fuzz value                  |
 *
 * CRITICAL: Direction Semantics ([in]/[out] relative to callee)
 * - For ECalls (Enclave is callee):
 *   [in] = Host→Enclave → FUZZ THIS in harness
 *   [out] = Enclave→Host → Allocate buffer only
 * - For OCalls (Host is callee):
 *   [in] = Enclave→Host → No fuzzing needed
 *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper
 *
 * ============================================================================
 * Memory Management (Two Approaches)
 * ============================================================================
 * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:
 * - Use calloc() + g_alloc_mgr.push_back() to track allocations
 * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically frees all
 * tracked memory after each iteration
 * - No explicit free() needed in harness functions
 * - Pros: Simple, no memory leaks, centralized cleanup
 * - Cons: Memory accumulates until end of iteration
 *
 * Approach 2 (Explicit free()):
 * - Use calloc() without g_alloc_mgr tracking
 * - Manually write free() calls at appropriate locations in harness code
 * - Pros: Immediate memory release, lower memory footprint
 * - Cons: Must ensure all allocations are freed, risk of memory leaks
 *
 * Usage: Choose approach based on your needs:
 * - Default: g_alloc_mgr for safety and simplicity
 * - Manual: Direct free() for memory-sensitive scenarios
 *
 * ============================================================================
 * Weighted Selection System
 * ============================================================================
 * Each harness has a weight (default: 10). Adjust weights in customized_init():
 * - High weight (e.g., 50-100) for critical/bottleneck paths
 * - Low weight (e.g., 1-5) for well-covered paths
 * - Modify test_harness_registry[i].weight before calculating total_weight
 *
 * ============================================================================
 */

#include "Enclave_u.h"
#include "FuzzedDataProvider.h"
#include <errno.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

template <typename T> constexpr size_t safe_sizeof() {
  return sizeof(
      typename std::conditional<std::is_void<T>::value, char, T>::type);
}

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern std::vector<uint8_t *> g_alloc_mgr;
extern sgx_enclave_id_t __g_harness_eid;

// Fuzzing configuration parameters
static size_t g_max_strlen = 128; // Max string length for [string] attributes
static size_t g_max_cnt = 32;     // Max count for unbounded arrays
static size_t g_max_size = 512;   // Max size for unbounded buffers

// ============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 10)
};

static TestHarnessEntry test_harness_registry[10240];
static unsigned int test_harness_count = 0;
static int total_weight = 0;

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data
// ============================================================================

extern "C" void _harness_ocall_print_string(const char *str) {
  ocall_print_string(str);
}

extern "C" void _harness_ocall_pointer_user_check(int *val) {
  ocall_pointer_user_check(val);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(int) < 8 ? (20 / sizeof(int)) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(int));
  }
}

extern "C" void _harness_ocall_pointer_in(int *val) { ocall_pointer_in(val); }

extern "C" void _harness_ocall_pointer_out(int *val) {
  ocall_pointer_out(val);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val = ((1) * (sizeof(int))) / sizeof(int);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(int));
  }
}

extern "C" void _harness_ocall_pointer_in_out(int *val) {
  ocall_pointer_in_out(val);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val = ((1) * (sizeof(int))) / sizeof(int);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(int));
  }
}

extern "C" void _harness_ocall_function_allow(void) { ocall_function_allow(); }

extern "C" void _harness_sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf) {
  sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
      g_fdp->ConsumeData(&cpuinfo[i_0_0], sizeof(int));
    }
  }
}

extern "C" int
_harness_sgx_thread_wait_untrusted_event_ocall(const void *self) {
  int _fuzz_ret = sgx_thread_wait_untrusted_event_ocall(self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_untrusted_event_ocall(const void *waiter) {
  int _fuzz_ret = sgx_thread_set_untrusted_event_ocall(waiter);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_setwait_untrusted_events_ocall(const void *waiter,
                                                   const void *self) {
  int _fuzz_ret = sgx_thread_setwait_untrusted_events_ocall(waiter, self);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_waiter =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)waiter, count_0_waiter * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_self =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)self, count_0_self * 1);
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

extern "C" int
_harness_sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters,
                                                        size_t total) {
  int _fuzz_ret =
      sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&_fuzz_ret, sizeof(int));
  }
  return _fuzz_ret;
}

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

static void _harness_ecall_type_char(void) {
  char val;
  g_fdp->ConsumeData(&val, sizeof(char));
  ecall_type_char(__g_harness_eid, val);
}
static void _harness_ecall_type_int(void) {
  int val;
  g_fdp->ConsumeData(&val, sizeof(int));
  ecall_type_int(__g_harness_eid, val);
}
static void _harness_ecall_type_float(void) {
  float val;
  g_fdp->ConsumeData(&val, sizeof(float));
  ecall_type_float(__g_harness_eid, val);
}
static void _harness_ecall_type_double(void) {
  double val;
  g_fdp->ConsumeData(&val, sizeof(double));
  ecall_type_double(__g_harness_eid, val);
}
static void _harness_ecall_type_size_t(void) {
  size_t val;
  g_fdp->ConsumeData(&val, sizeof(size_t));
  ecall_type_size_t(__g_harness_eid, val);
}
static void _harness_ecall_type_wchar_t(void) {
  wchar_t val;
  g_fdp->ConsumeData(&val, sizeof(wchar_t));
  ecall_type_wchar_t(__g_harness_eid, val);
}
static void _harness_ecall_type_struct(void) {
  struct struct_foo_t val;
  g_fdp->ConsumeData(&val, sizeof(struct struct_foo_t));
  ecall_type_struct(__g_harness_eid, val);
}
static void _harness_ecall_type_enum_union(void) {
  enum enum_foo_t val1;
  g_fdp->ConsumeData(&val1, sizeof(enum enum_foo_t));
  union union_foo_t *val2 = NULL;
  val2 = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val2 = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(union union_foo_t) < 8 ? (20 / sizeof(union union_foo_t)) : 1,
        g_max_cnt);
    val2 = (union union_foo_t *)calloc(count_0_val2, sizeof(union union_foo_t));
    g_alloc_mgr.push_back((uint8_t *)val2);
    g_fdp->ConsumeData((void *)val2, count_0_val2 * sizeof(union union_foo_t));
  }
  ecall_type_enum_union(__g_harness_eid, val1, val2);
}
static void _harness_ecall_pointer_user_check(void) {
  size_t _fuzz_ret;
  void *val = NULL;
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val =
        g_fdp->ConsumeIntegralInRange<size_t>(1 < 8 ? (20 / 1) : 1, g_max_cnt);
    val = (void *)calloc(count_0_val, 1);
    g_alloc_mgr.push_back((uint8_t *)val);
    g_fdp->ConsumeData((void *)val, count_0_val * 1);
  }
  size_t sz;
  g_fdp->ConsumeData(&sz, sizeof(size_t));
  ecall_pointer_user_check(__g_harness_eid, &_fuzz_ret, val, sz);
}
static void _harness_ecall_pointer_in(void) {
  int *val = NULL;
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val = ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    val = (int *)calloc(count_0_val, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)val);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(int));
  }
  ecall_pointer_in(__g_harness_eid, val);
}
static void _harness_ecall_pointer_out(void) {
  int *val = NULL;
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val = ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    val = (int *)calloc(count_0_val, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)val);
  }
  ecall_pointer_out(__g_harness_eid, val);
}
static void _harness_ecall_pointer_in_out(void) {
  int *val = NULL;
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val = ((1) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    val = (int *)calloc(count_0_val, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)val);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(int));
  }
  ecall_pointer_in_out(__g_harness_eid, val);
}
static void _harness_ecall_pointer_string(void) {
  char *str = NULL;
  size_t str_strlen = g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  str = (char *)calloc(str_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)str);
  g_fdp->ConsumeData(str, str_strlen * sizeof(char));
  ecall_pointer_string(__g_harness_eid, str);
}
static void _harness_ecall_pointer_string_const(void) {
  char *str = NULL;
  size_t str_strlen = g_fdp->ConsumeIntegralInRange<size_t>(0, g_max_strlen);
  str = (char *)calloc(str_strlen + 1, sizeof(char));
  g_alloc_mgr.push_back((uint8_t *)str);
  g_fdp->ConsumeData(str, str_strlen * sizeof(char));
  ecall_pointer_string_const(__g_harness_eid, str);
}
static void _harness_ecall_pointer_size(void) {
  void *ptr = NULL;
  size_t len;
  len = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
  ptr = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_ptr = ((1) * (len) + 1 - 1) / 1;
    ptr = (void *)calloc(count_0_ptr, 1);
    g_alloc_mgr.push_back((uint8_t *)ptr);
    g_fdp->ConsumeData((void *)ptr, count_0_ptr * 1);
  }
  ecall_pointer_size(__g_harness_eid, ptr, len);
}
static void _harness_ecall_pointer_count(void) {
  int *arr = NULL;
  size_t cnt;
  cnt = g_fdp->ConsumeIntegralInRange<size_t>(
      sizeof(size_t) < 8 ? (20 / sizeof(size_t)) : 1, g_max_cnt);
  arr = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_arr =
        ((cnt) * (sizeof(int)) + sizeof(int) - 1) / sizeof(int);
    arr = (int *)calloc(count_0_arr, sizeof(int));
    g_alloc_mgr.push_back((uint8_t *)arr);
    g_fdp->ConsumeData((void *)arr, count_0_arr * sizeof(int));
  }
  ecall_pointer_count(__g_harness_eid, arr, cnt);
}
static void _harness_ecall_pointer_isptr_readonly(void) {
  buffer_t buf = NULL;
  size_t len;
  len = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
  buf = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_buf =
        ((1) * (len) +
         safe_sizeof<typename std::remove_pointer<buffer_t>::type>() - 1) /
        safe_sizeof<typename std::remove_pointer<buffer_t>::type>();
    buf = (buffer_t)calloc(
        count_0_buf,
        safe_sizeof<typename std::remove_pointer<buffer_t>::type>());
    g_alloc_mgr.push_back((uint8_t *)buf);
    g_fdp->ConsumeData(
        (void *)buf,
        count_0_buf *
            safe_sizeof<typename std::remove_pointer<buffer_t>::type>());
  }
  ecall_pointer_isptr_readonly(__g_harness_eid, buf, len);
}
static void _harness_ocall_pointer_attr(void) {
  ocall_pointer_attr(__g_harness_eid);
}
static void _harness_ecall_array_user_check(void) {
  int arr[4];
  for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
    g_fdp->ConsumeData(&arr[i_0_0], sizeof(int));
  }
  ecall_array_user_check(__g_harness_eid, arr);
}
static void _harness_ecall_array_in(void) {
  int arr[4];
  for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
    g_fdp->ConsumeData(&arr[i_0_0], sizeof(int));
  }
  ecall_array_in(__g_harness_eid, arr);
}
static void _harness_ecall_array_out(void) {
  int arr[4];
  ecall_array_out(__g_harness_eid, arr);
}
static void _harness_ecall_array_in_out(void) {
  int arr[4];
  for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
    g_fdp->ConsumeData(&arr[i_0_0], sizeof(int));
  }
  ecall_array_in_out(__g_harness_eid, arr);
}
static void _harness_ecall_array_isary(void) {
  array_t arr;
  g_fdp->ConsumeData(&arr[0], 1);
  ecall_array_isary(__g_harness_eid, arr);
}
static void _harness_ecall_function_public(void) {
  ecall_function_public(__g_harness_eid);
}
static void _harness_ecall_function_private(void) {
  int _fuzz_ret;
  ecall_function_private(__g_harness_eid, &_fuzz_ret);
}
static void _harness_ecall_malloc_free(void) {
  ecall_malloc_free(__g_harness_eid);
}
static void _harness_ecall_sgx_cpuid(void) {
  int cpuinfo[4];
  int leaf;
  g_fdp->ConsumeData(&leaf, sizeof(int));
  ecall_sgx_cpuid(__g_harness_eid, cpuinfo, leaf);
}
static void _harness_ecall_exception(void) { ecall_exception(__g_harness_eid); }
static void _harness_ecall_map(void) { ecall_map(__g_harness_eid); }
static void _harness_ecall_increase_counter(void) {
  size_t _fuzz_ret;
  ecall_increase_counter(__g_harness_eid, &_fuzz_ret);
}
static void _harness_ecall_producer(void) { ecall_producer(__g_harness_eid); }
static void _harness_ecall_consumer(void) { ecall_consumer(__g_harness_eid); }
static void _harness_ecall_test_string_hooks(void) {
  ecall_test_string_hooks(__g_harness_eid);
}
static void _harness_ecall_test_string_hooks_oob(void) {
  int test_id;
  g_fdp->ConsumeData(&test_id, sizeof(int));
  ecall_test_string_hooks_oob(__g_harness_eid, test_id);
}

// ============================================================================
// Customized Initialization
// ============================================================================
// This function is called once during fuzzer initialization
// (LLVMFuzzerInitialize).
//
// REQUIRED: Register all test harnesses by filling test_harness_registry[]
//
// Usage:
//   test_harness_registry[test_harness_count++] = {harness_function, weight};
//
// IMPORTANT:
// - This function is called BEFORE any fuzzing iterations start
// - DO NOT create or initialize the enclave here (__g_harness_eid will be 0)
// - DO NOT access g_fdp here (it's not initialized yet)
// - Keep initialization lightweight and fast
// - Weight MUST be > 0 for all harnesses
//
// Optional: Add custom initialization such as:
// - Environment variable configuration (setenv, putenv)
// - Global state initialization
// - Logging/debugging setup
// - Resource pre-allocation
// - Configuration file loading
// ============================================================================

extern "C" void customized_init() {
  // ========================================================================
  // Step 1: Register all test harnesses
  // ========================================================================
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_char,
  //                                                10}; // Test ecall_type_char
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_int,
  //                                                10}; // Test ecall_type_int
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_float,
  //                                                10}; // Test
  //                                                ecall_type_float
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_double,
  //                                                10}; // Test
  //                                                ecall_type_double
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_size_t,
  //                                                10}; // Test
  //                                                ecall_type_size_t
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_wchar_t,
  //                                                10}; // Test
  //                                                ecall_type_wchar_t
  // test_harness_registry[test_harness_count++] = {_harness_ecall_type_struct,
  //                                                10}; // Test
  //                                                ecall_type_struct
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_type_enum_union, 10}; // Test ecall_type_enum_union
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_user_check, 10}; // Test
  //     ecall_pointer_user_check
  // test_harness_registry[test_harness_count++] = {_harness_ecall_pointer_in,
  //                                                10}; // Test
  //                                                ecall_pointer_in
  // test_harness_registry[test_harness_count++] = {_harness_ecall_pointer_out,
  //                                                10}; // Test
  //                                                ecall_pointer_out
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_in_out, 10}; // Test ecall_pointer_in_out
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_string, 10}; // Test ecall_pointer_string
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_string_const,
  //     10}; // Test ecall_pointer_string_const
  // test_harness_registry[test_harness_count++] = {_harness_ecall_pointer_size,
  //                                                10}; // Test
  //                                                ecall_pointer_size
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_count, 10}; // Test ecall_pointer_count
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_pointer_isptr_readonly,
  //     10}; // Test ecall_pointer_isptr_readonly
  // test_harness_registry[test_harness_count++] = {_harness_ocall_pointer_attr,
  //                                                10}; // Test
  //                                                ocall_pointer_attr
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_array_user_check, 10}; // Test ecall_array_user_check
  // test_harness_registry[test_harness_count++] = {_harness_ecall_array_in,
  //                                                10}; // Test ecall_array_in
  // test_harness_registry[test_harness_count++] = {_harness_ecall_array_out,
  //                                                10}; // Test ecall_array_out
  // test_harness_registry[test_harness_count++] = {_harness_ecall_array_in_out,
  //                                                10}; // Test
  //                                                ecall_array_in_out
  // test_harness_registry[test_harness_count++] = {_harness_ecall_array_isary,
  //                                                10}; // Test
  //                                                ecall_array_isary
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_function_public, 10}; // Test ecall_function_public
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_function_private, 10}; // Test ecall_function_private
  // test_harness_registry[test_harness_count++] = {_harness_ecall_malloc_free,
  //                                                10}; // Test
  //                                                ecall_malloc_free
  // test_harness_registry[test_harness_count++] = {_harness_ecall_sgx_cpuid,
  //                                                10}; // Test ecall_sgx_cpuid
  // test_harness_registry[test_harness_count++] = {_harness_ecall_exception,
  //                                                10}; // Test ecall_exception
  // test_harness_registry[test_harness_count++] = {_harness_ecall_map,
  //                                                10}; // Test ecall_map
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_increase_counter, 10}; // Test ecall_increase_counter
  // test_harness_registry[test_harness_count++] = {_harness_ecall_producer,
  //                                                10}; // Test ecall_producer
  // test_harness_registry[test_harness_count++] = {_harness_ecall_consumer,
  //                                                10}; // Test ecall_consumer
  // test_harness_registry[test_harness_count++] = {
  //     _harness_ecall_test_string_hooks, 10}; // Test ecall_test_string_hooks
  test_harness_registry[test_harness_count++] = {
      _harness_ecall_test_string_hooks_oob,
      10}; // Test ecall_test_string_hooks_oob

  // ========================================================================
  // Step 2: Calculate total weight for weighted random selection
  // ========================================================================

  // Sanity check: ensure at least one harness is registered
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }

  total_weight = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    total_weight += test_harness_registry[i].weight;
  }

  // Sanity check: ensure total weight > 0
  if (total_weight == 0) {
    fprintf(stderr, "[!] Error: All harness weights are 0\n");
    abort();
  }

  // ========================================================================
  // Step 3: Custom initialization (optional)
  // ========================================================================
  // Examples:
  // - setenv("SGX_AESM_ADDR", "1", 1);
  // - freopen("/tmp/fuzzer.log", "w", stderr);
  // - Initialize global variables
  // - Pre-load configuration files
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration
// Performs weighted random selection of test harnesses
// ============================================================================

extern "C" void customized_harness(void) {
  // Weighted random selection
  do {
    int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
    int cumulative = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
      cumulative += test_harness_registry[i].weight;
      if (rand_val < cumulative) {
        test_harness_registry[i].function();
        break;
      }
    }
  } while (g_fdp->remaining_bytes() > 0);
}
