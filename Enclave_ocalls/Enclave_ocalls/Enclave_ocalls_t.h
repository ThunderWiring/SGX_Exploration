#ifndef ENCLAVE_OCALLS_T_H__
#define ENCLAVE_OCALLS_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void OcallFunctions_Enclave();

sgx_status_t SGX_CDECL Ocall_printf(char* str);
sgx_status_t SGX_CDECL Ocall_time(char* outTime, size_t len);
sgx_status_t SGX_CDECL Ocall_open(const char* filename, unsigned int* fd, size_t len);
sgx_status_t SGX_CDECL Ocall_write(char* data, unsigned int* fd, size_t len);
sgx_status_t SGX_CDECL Ocall_close(unsigned int* fd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
