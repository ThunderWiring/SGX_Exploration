#include "Enclave_DivideZero_u.h"
#include <errno.h>


typedef struct ms_Ocall_printf_t {
	char* ms_str;
} ms_Ocall_printf_t;

static sgx_status_t SGX_CDECL Enclave_DivideZero_Ocall_printf(void* pms)
{
	ms_Ocall_printf_t* ms = SGX_CAST(ms_Ocall_printf_t*, pms);
	Ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave_DivideZero = {
	1,
	{
		(void*)(uintptr_t)Enclave_DivideZero_Ocall_printf,
	}
};

sgx_status_t Enclave_DivideByZero(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_DivideZero, NULL);
	return status;
}

