#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_DivideZero_u.h"
#include "sgx_trts_exception.h"
#define ENCLAVE_FILE _T("Enclave_DivideZero.signed.dll")
sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}
void Ocall_printf( char* str) {
	printf("%s\n", str);
}

int _tmain(int argc, _TCHAR* argv[]) {
	sgx_enclave_id_t eid;
	sgx_status_t res = createEnclave(&eid);
	if (res != SGX_SUCCESS) {
		printf("[App]: error-, failed to create enclave.\n");
		return -1;
	} else {
		printf("[App]: Enclave created!\n");
	}
	Enclave_DivideByZero(eid);
	printf("[App]: done\n");
	return 0;
}

