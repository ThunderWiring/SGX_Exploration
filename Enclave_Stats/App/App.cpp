#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_Stats_u.h"
#include <vector> 
#include <thread>

#define ENCLAVE_FILE _T("Enclave_Stats.signed.dll")
using namespace std;

sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}

 
int _tmain(int argc, _TCHAR* argv[]) {
	int counter = 0;
	while(1) {
		sgx_enclave_id_t	eid;
		if (createEnclave(&eid) != SGX_SUCCESS) {
			printf("App: error-, failed to create enclave.\n");
			return -1;
		} else {	
			counter++;
			printf("Enclave #%d created - eid = %x\n", counter, eid);
			Enclave_EmptyFunc(eid);
		}
	}
	return 0;
}

