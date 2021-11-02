#include "../App.h"
#include "Enclave_u.h"

void sgxsan_test_edge_check(void)
{
    // test sgxsan_edge_check
    void *ssa = nullptr;
    ecall_get_ssa_addr(global_eid, &ssa);
    ecall_use_ssa_addr(global_eid, ssa);
    int test_arr[5][6][7] = {{{0}}};
    ecall_use_array(global_eid, test_arr);
}

int *ocall_test(int **ptr)
{
    *ptr = (int *)ocall_test;
    return (int *)sgxsan_test_edge_check;
}