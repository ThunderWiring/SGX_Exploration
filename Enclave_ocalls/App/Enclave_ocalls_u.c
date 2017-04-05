#include "Enclave_ocalls_u.h"
#include <errno.h>


typedef struct ms_Ocall_printf_t {
	char* ms_str;
} ms_Ocall_printf_t;

typedef struct ms_Ocall_time_t {
	char* ms_outTime;
	size_t ms_len;
} ms_Ocall_time_t;

typedef struct ms_Ocall_open_t {
	char* ms_filename;
	unsigned int* ms_fd;
	size_t ms_len;
} ms_Ocall_open_t;

typedef struct ms_Ocall_write_t {
	char* ms_data;
	unsigned int* ms_fd;
	size_t ms_len;
} ms_Ocall_write_t;

typedef struct ms_Ocall_close_t {
	unsigned int* ms_fd;
} ms_Ocall_close_t;

static sgx_status_t SGX_CDECL Enclave_ocalls_Ocall_printf(void* pms)
{
	ms_Ocall_printf_t* ms = SGX_CAST(ms_Ocall_printf_t*, pms);
	Ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocalls_Ocall_time(void* pms)
{
	ms_Ocall_time_t* ms = SGX_CAST(ms_Ocall_time_t*, pms);
	Ocall_time(ms->ms_outTime, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocalls_Ocall_open(void* pms)
{
	ms_Ocall_open_t* ms = SGX_CAST(ms_Ocall_open_t*, pms);
	Ocall_open((const char*)ms->ms_filename, ms->ms_fd, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocalls_Ocall_write(void* pms)
{
	ms_Ocall_write_t* ms = SGX_CAST(ms_Ocall_write_t*, pms);
	Ocall_write(ms->ms_data, ms->ms_fd, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocalls_Ocall_close(void* pms)
{
	ms_Ocall_close_t* ms = SGX_CAST(ms_Ocall_close_t*, pms);
	Ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_Enclave_ocalls = {
	5,
	{
		(void*)(uintptr_t)Enclave_ocalls_Ocall_printf,
		(void*)(uintptr_t)Enclave_ocalls_Ocall_time,
		(void*)(uintptr_t)Enclave_ocalls_Ocall_open,
		(void*)(uintptr_t)Enclave_ocalls_Ocall_write,
		(void*)(uintptr_t)Enclave_ocalls_Ocall_close,
	}
};

sgx_status_t OcallFunctions_Enclave(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_ocalls, NULL);
	return status;
}

