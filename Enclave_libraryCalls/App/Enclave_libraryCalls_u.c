#include "Enclave_libraryCalls_u.h"
#include <errno.h>


static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave_libraryCalls = {
	0,
	{ NULL },
};

sgx_status_t libraryCalls_Enclave(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave_libraryCalls, NULL);
	return status;
}

