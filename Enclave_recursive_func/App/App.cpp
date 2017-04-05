#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_recursive_func_u.h"
#define ENCLAVE_FILE _T("Enclave_recursive_func.signed.dll")

//#define ENCLAVE
#define ENCLAVE
#define FIBONACCI
//#define FACTORIAL

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

//#ifdef FACTORIAL
const int FACT_CONST = 25;
static int aux_factorial (int num) {
	if(num == 1) return num;
	return num * aux_factorial(num-1);
}
int factorial_NoEnclave() {
	return aux_factorial(FACT_CONST);
}

const int FIB_CONST= 10;
int fibonacci_NoEnclave(int num) {
	if(num == 1 || num == 0) return num;
	else if(num < 0) return -1;
	return fibonacci_NoEnclave(num-1) + fibonacci_NoEnclave(num-2);
}

int _tmain(int argc, _TCHAR* argv[])
{
	int* res = new int;
	*res = 0;
#ifdef ENCLAVE
	sgx_enclave_id_t	eid;
	if (createEnclave(&eid) != SGX_SUCCESS) {
		printf("App: error-, failed to create enclave.\n");
		return -1;
	} else {
		printf("Enclave created!\n");
	}	
	printf("[Enclave]");
	
	for(long long i(0); i < ITERATIONS; ++i) {
			fibonacci_Enclave(eid, (int*)res, sizeof(int));
			//factorial_Enclave(eid, (int*)res, sizeof(int));
	}
	printf("res = %d\n", *res);
#endif
	
#ifdef NO_ENCLAVE
	printf("[NoEnclave]");	
	for(long long i(0); i < ITERATIONS; ++i) {		
	#ifdef FIBONACCI
		fibonacci_NoEnclave(FIB_CONST);
	#endif
	
	//#ifdef FACTORIAL
	//	factorial_NoEnclave();
	//#endif	
	}
#endif
	return 0;
}