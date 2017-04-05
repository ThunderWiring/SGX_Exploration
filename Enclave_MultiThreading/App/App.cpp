#include "stdafx.h"
#include <vector>
#include <stdlib.h>  
#include <chrono>
#include <windows.h>   // WinApi header
#include <stdio.h>
#include <time.h>
#include <thread>
#include <iostream>
#include "sgx_urts.h"
#include "Enclave_MultiThreading_u.h"
#define ENCLAVE_FILE _T("Enclave_MultiThreading.signed.dll")
using namespace std;

static const int NUMBER_OF_THREADS = 50;
int global_thread_count  = 0;
typedef struct _app_api_datastruct {
	sgx_enclave_id_t eid; 
	int id;
} App_Api_Struct;

void Ocall_printf(char* str, int* num) {
	if(num != NULL) {
	  printf("   %s %d \n",str,  *num);
	} else { 
		printf("   %s\n", str);
	}
}


static sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}

static void App_Read(App_Api_Struct& data) {
	sgx_status_t ret = Enclave_Read(data.eid, &(data.id), sizeof(int));
}

static void App_write(App_Api_Struct& data) {
	Enclave_Write(data.eid, &(data.id), sizeof(int));
}

int _tmain(int argc, _TCHAR* argv[])
{
	sgx_enclave_id_t eid;
	sgx_status_t res = createEnclave(&eid);
	if (res != SGX_SUCCESS) {
		printf("[APP] Error - failed to create enclave.\n");
		return -1;
	} else {
		printf("[APP] Enclave created!\n");
	}
	Enclave_Init(eid);
	App_Api_Struct threadData[NUMBER_OF_THREADS];
	vector<thread> threads = vector<thread>();
	for(int i(0); i <= NUMBER_OF_THREADS; ++i) {
		threadData[i].eid = eid;
		threadData[i].id = i;
		threads.push_back(std::thread(App_Read, threadData[i]));
		threads.push_back(std::thread(App_write, threadData[i]));
	}	

	for(auto& thr : threads) {
		thr.join();
	}
	return 0;
}

