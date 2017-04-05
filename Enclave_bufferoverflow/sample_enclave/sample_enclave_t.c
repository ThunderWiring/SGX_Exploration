#include "sample_enclave_t.h"

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_Enclave_Authenticate(void* pms)
{
	ms_Enclave_Authenticate_t* ms = SGX_CAST(ms_Enclave_Authenticate_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	char* _tmp_password = ms->ms_password;
	size_t _len_password = _tmp_password ? strlen(_tmp_password) + 1 : 0;
	char* _in_password = NULL;
	int* _tmp_res = ms->ms_res;
	size_t _len_res = sizeof(*_tmp_res);
	int* _in_res = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_Enclave_Authenticate_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_password != NULL) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
		_in_password[_len_password - 1] = '\0';
	}
	if (_tmp_res != NULL) {
		if ((_in_res = (int*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}
	Enclave_Authenticate(_in_user, _in_password, _in_res);
err:
	if (_in_user) free(_in_user);
	if (_in_password) free(_in_password);
	if (_in_res) {
		memcpy(_tmp_res, _in_res, _len_res);
		free(_in_res);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_Enclave_GetGrades(void* pms)
{
	ms_Enclave_GetGrades_t* ms = SGX_CAST(ms_Enclave_GetGrades_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_user = ms->ms_user;
	size_t _len_user = _tmp_user ? strlen(_tmp_user) + 1 : 0;
	char* _in_user = NULL;
	int* _tmp_arr_out = ms->ms_arr_out;
	size_t _tmp_len = ms->ms_len;
	size_t _len_arr_out = _tmp_len;
	int* _in_arr_out = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_Enclave_GetGrades_t));
	CHECK_UNIQUE_POINTER(_tmp_user, _len_user);
	CHECK_UNIQUE_POINTER(_tmp_arr_out, _len_arr_out);

	if (_tmp_user != NULL) {
		_in_user = (char*)malloc(_len_user);
		if (_in_user == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_user, _tmp_user, _len_user);
		_in_user[_len_user - 1] = '\0';
	}
	if (_tmp_arr_out != NULL) {
		if ((_in_arr_out = (int*)malloc(_len_arr_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr_out, 0, _len_arr_out);
	}
	Enclave_GetGrades(_in_user, _in_arr_out, _tmp_len);
err:
	if (_in_user) free(_in_user);
	if (_in_arr_out) {
		memcpy(_tmp_arr_out, _in_arr_out, _len_arr_out);
		free(_in_arr_out);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_Enclave_Authenticate, 0},
		{(void*)(uintptr_t)sgx_Enclave_GetGrades, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][2];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL print(const char* string)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_string = string ? strlen(string) + 1 : 0;

	ms_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_t);
	void *__tmp = NULL;

	ocalloc_size += (string != NULL && sgx_is_within_enclave(string, _len_string)) ? _len_string : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_t));

	if (string != NULL && sgx_is_within_enclave(string, _len_string)) {
		ms->ms_string = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_string);
		memcpy((void*)ms->ms_string, string, _len_string);
	} else if (string == NULL) {
		ms->ms_string = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_ptr(uintptr_t ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_print_ptr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_ptr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_ptr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_ptr_t));

	ms->ms_ptr = ptr;
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_int(int x)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_print_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_int_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_int_t));

	ms->ms_x = x;
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
