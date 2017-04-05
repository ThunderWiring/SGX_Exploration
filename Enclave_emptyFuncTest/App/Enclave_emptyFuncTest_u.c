#include "Enclave_emptyFuncTest_u.h"
#include <errno.h>


static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave_emptyFuncTest = {
	0,
	{ NULL },
};

sgx_status_t EmptyFunc_Enclave(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_emptyFuncTest, NULL);
	return status;
}

