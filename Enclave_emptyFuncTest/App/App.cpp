// App.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_emptyFuncTest_u.h"
 
#define ENCLAVE

#define ENCLAVE_FILE _T("Enclave_emptyFuncTest.signed.dll")

const long long ITERATIONS = 1000000;


#ifdef ENCLAVE
sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	// Create the Enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}
#endif

#ifdef NO_ENCLAVE
void EmptyFunc_NoEnclave() {
	/* Does Nothing */
}
#endif

int _tmain(int argc, _TCHAR* argv[])
{
#ifdef ENCLAVE
	/* Creating Enclave */
	sgx_enclave_id_t	eid;
	if (createEnclave(&eid) != SGX_SUCCESS) {
		printf("App: error-, failed to create enclave.\n");
		return -1;
	} else {
		printf("Enclave created!\n");
	}
	
	/* calling the Enclave's empty function */
	printf("[Enclave]");
	for(long long i(0); i < ITERATIONS; ++i) {
		EmptyFunc_Enclave(eid);
	}
#endif

#ifdef NO_ENCLAVE
	printf("[No Enclave]");
	/* calling empty function without Enclave */
	for(long long i(0); i < ITERATIONS; ++i) {
		EmptyFunc_NoEnclave();
	}
#endif

	return 0;
}