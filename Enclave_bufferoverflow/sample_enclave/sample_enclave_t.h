#ifndef SAMPLE_ENCLAVE_T_H__
#define SAMPLE_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void Enclave_Authenticate(char* user, char* password, int* res);
void Enclave_GetGrades(char* user, int* arr_out, size_t len);

sgx_status_t SGX_CDECL print(const char* string);
sgx_status_t SGX_CDECL print_ptr(uintptr_t ptr);
sgx_status_t SGX_CDECL print_int(int x);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
