#include "Enclave_recursive_func_u.h"
#include <errno.h>

typedef struct ms_factorial_Enclave_t {
	int* ms_res;
	size_t ms_size;
} ms_factorial_Enclave_t;

typedef struct ms_fibonacci_Enclave_t {
	int* ms_res;
	size_t ms_size;
} ms_fibonacci_Enclave_t;

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave_recursive_func = {
	0,
	{ NULL },
};

sgx_status_t factorial_Enclave(sgx_enclave_id_t eid, int* res, size_t size)
{
	sgx_status_t status;
	ms_factorial_Enclave_t ms;
	ms.ms_res = res;
	ms.ms_size = size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_recursive_func, &ms);
	return status;
}

sgx_status_t fibonacci_Enclave(sgx_enclave_id_t eid, int* res, size_t size)
{
	sgx_status_t status;
	ms_fibonacci_Enclave_t ms;
	ms.ms_res = res;
	ms.ms_size = size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave_recursive_func, &ms);
	return status;
}

