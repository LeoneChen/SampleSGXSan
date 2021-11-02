#include <stddef.h>
#include <stdint.h>

#include "Enclave_t.h"

typedef size_t sys_word_t;

typedef struct _thread_data_t
{
    sys_word_t self_addr;
    sys_word_t last_sp;          /* set by urts, relative to TCS */
    sys_word_t stack_base_addr;  /* set by urts, relative to TCS */
    sys_word_t stack_limit_addr; /* set by urts, relative to TCS */
    sys_word_t first_ssa_gpr;    /* set by urts, relative to TCS */
    sys_word_t stack_guard;      /* GCC expects start_guard at 0x14 on x86 and 0x28 on x64 */

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

int g_arr[4];

void ecall_get_ssa_addr(void **ssa)
{
    // detect global oob
    // g_arr[4] = 1;

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

void ecall_use_ssa_addr(void *ssa)
{
    int val = *(int *)(global_addr + 1);
    (void)val;
    (void)ssa;
}

void ecall_use_array(int arr[5][6][7])
{
    int a = arr[2][3][4];
    (void)a;
    // int b = arr[5][6];
    // (void)b;
}