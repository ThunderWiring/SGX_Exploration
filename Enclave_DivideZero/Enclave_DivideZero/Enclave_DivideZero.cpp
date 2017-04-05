#include "Enclave_DivideZero_t.h"
#include "sgx_trts_exception.h"
#include "sgx_trts.h"
int handler_DivideByZero(sgx_exception_info_t* info) {	
	//return EXCEPTION_CONTINUE_EXECUTION;
	return EXCEPTION_CONTINUE_SEARCH;
}

void Enclave_DivideByZero() {
	/*if (sgx_register_exception_handler(1, handler_DivideByZero) == NULL) {
		Ocall_printf(" [Enclave]: handler register failed");
	} else {
		Ocall_printf(" [Enclave]: handler register success");
	}*/
	int a(1);
	int b(3/(a-a)); // <-- exception thrown - divide by 0
	Ocall_printf(" [Enclave]: Resuming after handling exception");
}

  