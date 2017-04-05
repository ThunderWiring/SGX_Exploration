#include "Enclave_ocalls_t.h"
#include "sgx_trts.h"

#include <stdlib.h>
#include <string.h>
using namespace std;

void OcallFunctions_Enclave() {
	Ocall_printf("[Enclave] - printing message..");
	char local_time[26] = {'\0'};
	Ocall_time((local_time), 26);
	Ocall_printf( local_time);
	unsigned int fd = 0;
	Ocall_open("logging.txt", &fd, sizeof(unsigned int*));
	Ocall_write(local_time, &fd, sizeof(unsigned int*));
	Ocall_close(&fd);
}