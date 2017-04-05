#include "Enclave_recursive_func_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_factorial_Enclave_t {
	int* ms_res;
	size_t ms_size;
} ms_factorial_Enclave_t;

typedef struct ms_fibonacci_Enclave_t {
	int* ms_res;
	size_t ms_size;
} ms_fibonacci_Enclave_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_factorial_Enclave(void* pms)
{
	ms_factorial_Enclave_t* ms = SGX_CAST(ms_factorial_Enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_res = ms->ms_res;
	size_t _tmp_size = ms->ms_size;
	size_t _len_res = _tmp_size;
	int* _in_res = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_factorial_Enclave_t));
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	if (_tmp_res != NULL) {
		_in_res = (int*)malloc(_len_res);
		if (_in_res == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_res, _tmp_res, _len_res);
	}
	factorial_Enclave(_in_res, _tmp_size);
err:
	if (_in_res) {
		memcpy(_tmp_res, _in_res, _len_res);
		free(_in_res);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_fibonacci_Enclave(void* pms)
{
	ms_fibonacci_Enclave_t* ms = SGX_CAST(ms_fibonacci_Enclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_res = ms->ms_res;
	size_t _tmp_size = ms->ms_size;
	size_t _len_res = _tmp_size;
	int* _in_res = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_fibonacci_Enclave_t));
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	if (_tmp_res != NULL) {
		_in_res = (int*)malloc(_len_res);
		if (_in_res == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_res, _tmp_res, _len_res);
	}
	fibonacci_Enclave(_in_res, _tmp_size);
err:
	if (_in_res) {
		memcpy(_tmp_res, _in_res, _len_res);
		free(_in_res);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_factorial_Enclave, 0},
		{(void*)(uintptr_t)sgx_fibonacci_Enclave, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


#ifdef _MSC_VER
#pragma warning(pop)
#endif
