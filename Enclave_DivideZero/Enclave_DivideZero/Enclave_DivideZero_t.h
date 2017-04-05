#ifndef ENCLAVE_DIVIDEZERO_T_H__
#define ENCLAVE_DIVIDEZERO_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void Enclave_DivideByZero();

sgx_status_t SGX_CDECL Ocall_printf(char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
