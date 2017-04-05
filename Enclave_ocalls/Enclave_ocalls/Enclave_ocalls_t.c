#include "Enclave_ocalls_t.h"

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_OcallFunctions_Enclave(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	OcallFunctions_Enclave();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_OcallFunctions_Enclave, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][1];
} g_dyn_entry_table = {
	5,
	{
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL Ocall_printf(char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_Ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_printf_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_printf_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy(ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_time(char* outTime, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_outTime = len;

	ms_Ocall_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_time_t);
	void *__tmp = NULL;

	ocalloc_size += (outTime != NULL && sgx_is_within_enclave(outTime, _len_outTime)) ? _len_outTime : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_time_t));

	if (outTime != NULL && sgx_is_within_enclave(outTime, _len_outTime)) {
		ms->ms_outTime = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_outTime);
		memset(ms->ms_outTime, 0, _len_outTime);
	} else if (outTime == NULL) {
		ms->ms_outTime = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (outTime) memcpy((void*)outTime, ms->ms_outTime, _len_outTime);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_open(const char* filename, unsigned int* fd, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_fd = len;

	ms_Ocall_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_open_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) ? _len_fd : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_open_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) {
		ms->ms_fd = (unsigned int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fd);
		memset(ms->ms_fd, 0, _len_fd);
	} else if (fd == NULL) {
		ms->ms_fd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(2, ms);

	if (fd) memcpy((void*)fd, ms->ms_fd, _len_fd);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_write(char* data, unsigned int* fd, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data ? strlen(data) + 1 : 0;
	size_t _len_fd = len;

	ms_Ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_write_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;
	ocalloc_size += (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) ? _len_fd : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_write_t));

	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) {
		ms->ms_fd = (unsigned int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fd);
		memcpy(ms->ms_fd, fd, _len_fd);
	} else if (fd == NULL) {
		ms->ms_fd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(3, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Ocall_close(unsigned int* fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fd = sizeof(*fd);

	ms_Ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Ocall_close_t);
	void *__tmp = NULL;

	ocalloc_size += (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) ? _len_fd : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Ocall_close_t));

	if (fd != NULL && sgx_is_within_enclave(fd, _len_fd)) {
		ms->ms_fd = (unsigned int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fd);
		memcpy(ms->ms_fd, fd, _len_fd);
	} else if (fd == NULL) {
		ms->ms_fd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);


	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
