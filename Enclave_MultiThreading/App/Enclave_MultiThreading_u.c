#include "Enclave_MultiThreading_u.h"
#include <errno.h>

typedef struct ms_Enclave_Read_t {
	int* ms_thread_id;
	size_t ms_len;
} ms_Enclave_Read_t;

typedef struct ms_Enclave_Write_t {
	int* ms_thread_id;
	size_t ms_len;
} ms_Enclave_Write_t;


typedef struct ms_Ocall_printf_t {
	char* ms_str;
	int* ms_num;
} ms_Ocall_printf_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_MultiThreading_Ocall_printf(void* pms)
{
	ms_Ocall_printf_t* ms = SGX_CAST(ms_Ocall_printf_t*, pms);
	Ocall_printf(ms->ms_str, ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MultiThreading_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MultiThreading_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MultiThreading_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MultiThreading_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MultiThreading_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_Enclave_MultiThreading = {
	6,
	{
		(void*)(uintptr_t)Enclave_MultiThreading_Ocall_printf,
		(void*)(uintptr_t)Enclave_MultiThreading_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_MultiThreading_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_MultiThreading_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_MultiThreading_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_MultiThreading_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t Enclave_Read(sgx_enclave_id_t eid, int* thread_id, size_t len)
{
	sgx_status_t status;
	ms_Enclave_Read_t ms;
	ms.ms_thread_id = thread_id;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_MultiThreading, &ms);
	return status;
}

sgx_status_t Enclave_Write(sgx_enclave_id_t eid, int* thread_id, size_t len)
{
	sgx_status_t status;
	ms_Enclave_Write_t ms;
	ms.ms_thread_id = thread_id;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave_MultiThreading, &ms);
	return status;
}

sgx_status_t Enclave_Init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave_MultiThreading, NULL);
	return status;
}

