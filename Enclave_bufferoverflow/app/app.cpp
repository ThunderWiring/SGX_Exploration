#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "sample_enclave_u.h"
 
#define ENCLAVE_FILE _T("sample_enclave.signed.dll")
#define PASS_LENGTH 4
#define USER_LENGTH 30
#include <string>

//ocall:
void print_int(int x) {
	printf("%d\n", x);
}
void print_ptr(uintptr_t ptr) {
	printf("0x%x\n", ptr);
	ptr = 0;
}
void print(const char* str) {
	printf("%s\n", str);
	str = NULL;
}

static const int FAIL = 0;
static const int SUCCESS = 1;

void getStr(char buffer[]) {
	char c;
	int idx(0);
	do {
		 c = getchar();
		buffer[idx++] = c;
	} while(c != '\n');
	buffer[--idx] = '\0';
}

sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}

char buf_user[USER_LENGTH ] = { 0 };
char buf_pass[PASS_LENGTH ] = { 0 };


static bool App_Authenticate(sgx_enclave_id_t eid, char* buf_user, char* buf_pass) {
	int is_valid = FAIL;
	Enclave_Authenticate(eid, buf_user, buf_pass, &is_valid);
	if(is_valid == SUCCESS && strcmp(buf_user, "guy") == 0) {
		return true;
	} else if(is_valid == SUCCESS && strcmp(buf_user, "bassam") == 0) {
		return true;
	} else {
		printf("INVALID - try again\n\n");
		return false;
	}
}

void toUser(int gradesArr[], int len) {
	printf("Grades: ");
	for(int i = 0; i < len ; i++) {
		if(i <= 2) {
			printf("%d ", gradesArr[i]);
		} else {
			printf("\nHis Password: %s\n\n", gradesArr + i);
			return;
		}
	}
	printf("\n\n");
}

int main() {
	int i;
	sgx_enclave_id_t eid;
	sgx_status_t res = createEnclave(&eid);
	if (res != SGX_SUCCESS) {
		printf("[App]: error-, failed to create enclave.\n");
		return -1;
	} 
	printf("***********  WELCOME to UG TECHNION  ***********  \n"
		   "> please enter username and password:\n");
	do {
		printf("> ");
		getStr(buf_user);
		getStr(buf_pass);
		printf("\n");
	} while(App_Authenticate(eid, buf_user, buf_pass) == false);

	printf("Enter number of last grades to display:\n");
	int num_of_grades = 0;
	scanf_s("%d", &num_of_grades);
	int* arr = (int*) malloc(num_of_grades * sizeof(int));
	if(arr == NULL) {
		return -1;
	}
	size_t len = num_of_grades * sizeof(int);
	Enclave_GetGrades(eid, buf_user, arr, len);
	toUser(arr, num_of_grades);

	if(SGX_SUCCESS != sgx_destroy_enclave(eid)) {
		return -1;
	}
	return 0;
}