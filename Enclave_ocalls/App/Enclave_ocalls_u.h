#ifndef ENCLAVE_OCALLS_U_H__
#define ENCLAVE_OCALLS_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_printf, (char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_time, (char* outTime, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_open, (const char* filename, unsigned int* fd, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_write, (char* data, unsigned int* fd, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_close, (unsigned int* fd));

sgx_status_t OcallFunctions_Enclave(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
