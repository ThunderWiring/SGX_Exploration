#include "stdafx.h"
#define ENCLAVE

using namespace std;
#define ENCLAVE_FILE _T("Enclave_ocalls.signed.dll")
const long long ITERATIONS = 1000;
void Ocall_printf(char* str) {
	printf("[Ocall prinf] - %s\n", str);
}
void Ocall_time(char* outTime, size_t len) {
	time_t seconds = time(NULL);
	char buf[26] = {'\0'};
	ctime_s(buf, 26, &seconds);
	memcpy(outTime, buf, 26);
}

void Ocall_open(const char* filename, unsigned int* fd, size_t len) {
    FILE* _fd;
	fopen_s(&_fd, filename, "a+");
	*fd = (unsigned int)_fd;
}

void Ocall_write(char* data, unsigned int* fd, size_t len) {
	FILE* _fd = (FILE*)(*fd);
	fwrite(data, sizeof(char), strlen(data), _fd);
}

void Ocall_close(unsigned int* fd) {
    fclose((FILE*)(*fd));
}

#ifdef ENCLAVE
sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}
#endif

#ifdef NO_ENCLAVE
	void OcallFunctions_NoEnclave() {
		Ocall_printf("[No_Enclave] - printing message..");
		char local_time[26] = {'\0'};
		Ocall_time((local_time), 26);
		Ocall_printf( local_time);
		unsigned int fd = 0;
		Ocall_open("logging.txt", &fd, sizeof(unsigned int*));
		Ocall_write(local_time, &fd, sizeof(unsigned int*));
		Ocall_close(&fd);
	}
#endif

int _tmain(int argc, _TCHAR* argv[]) {
#ifdef ENCLAVE
	sgx_enclave_id_t eid;
	sgx_status_t res = createEnclave(&eid);
	if (res != SGX_SUCCESS) {
		printf("App: error-, failed to create enclave.\n");
		return -1;
	} else {
		printf("Enclave created!\n");
	}
	for(long long i = 0; i < ITERATIONS; ++i) {
		OcallFunctions_Enclave(eid);
	}
#endif

#ifdef NO_ENCLAVE
	for(long long i = 0; i < ITERATIONS; ++i) {
		OcallFunctions_NoEnclave();
	}
#endif
	remove("logging.txt");
	return 0;
}

