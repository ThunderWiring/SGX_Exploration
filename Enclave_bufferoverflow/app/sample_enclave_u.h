#ifndef SAMPLE_ENCLAVE_U_H__
#define SAMPLE_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, print, (const char* string));
void SGX_UBRIDGE(SGX_NOCONVENTION, print_ptr, (uintptr_t ptr));
void SGX_UBRIDGE(SGX_NOCONVENTION, print_int, (int x));

sgx_status_t Enclave_Authenticate(sgx_enclave_id_t eid, char* user, char* password, int* res);
sgx_status_t Enclave_GetGrades(sgx_enclave_id_t eid, char* user, int* arr_out, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
