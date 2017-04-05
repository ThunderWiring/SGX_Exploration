#include "sample_enclave_u.h"
#include <errno.h>

typedef struct ms_Enclave_Authenticate_t {
	char* ms_user;
	char* ms_password;
	int* ms_res;
} ms_Enclave_Authenticate_t;

typedef struct ms_Enclave_GetGrades_t {
	char* ms_user;
	int* ms_arr_out;
	size_t ms_len;
} ms_Enclave_GetGrades_t;

typedef struct ms_print_t {
	char* ms_string;
} ms_print_t;

typedef struct ms_print_ptr_t {
	uintptr_t ms_ptr;
} ms_print_ptr_t;

typedef struct ms_print_int_t {
	int ms_x;
} ms_print_int_t;

static sgx_status_t SGX_CDECL sample_enclave_print(void* pms)
{
	ms_print_t* ms = SGX_CAST(ms_print_t*, pms);
	print((const char*)ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sample_enclave_print_ptr(void* pms)
{
	ms_print_ptr_t* ms = SGX_CAST(ms_print_ptr_t*, pms);
	print_ptr(ms->ms_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL sample_enclave_print_int(void* pms)
{
	ms_print_int_t* ms = SGX_CAST(ms_print_int_t*, pms);
	print_int(ms->ms_x);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[3];
} ocall_table_sample_enclave = {
	3,
	{
		(void*)(uintptr_t)sample_enclave_print,
		(void*)(uintptr_t)sample_enclave_print_ptr,
		(void*)(uintptr_t)sample_enclave_print_int,
	}
};

sgx_status_t Enclave_Authenticate(sgx_enclave_id_t eid, char* user, char* password, int* res)
{
	sgx_status_t status;
	ms_Enclave_Authenticate_t ms;
	ms.ms_user = user;
	ms.ms_password = password;
	ms.ms_res = res;
	status = sgx_ecall(eid, 0, &ocall_table_sample_enclave, &ms);
	return status;
}

sgx_status_t Enclave_GetGrades(sgx_enclave_id_t eid, char* user, int* arr_out, size_t len)
{
	sgx_status_t status;
	ms_Enclave_GetGrades_t ms;
	ms.ms_user = user;
	ms.ms_arr_out = arr_out;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_sample_enclave, &ms);
	return status;
}

