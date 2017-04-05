// sample_enclave.cpp
#include "sample_enclave_t.h"
#include <string.h>
#define PASS_LENGTH  4

int grades_Guy[3] = {100, 99, 50};
char CORRECT_PASS_GUY[] = "123";
int grades_Bassam[3] = {76, 88, 28};
char CORRECT_PASS_BASSAM[] = "asd";


static const int FAIL = 0;
static const int SUCCESS = 1;

char buffer[PASS_LENGTH ] = {'\0'};
int pass = 0;


void Enclave_GetGrades(char* user, int* arr_out, size_t len) {
	if(strcmp(user, "guy") == 0) {
		memcpy(arr_out, grades_Guy, len);
	} else if( strcmp(user, "bassam") == 0 ) {
		memcpy(arr_out, grades_Bassam, len);
	}
}

void Enclave_Authenticate (char* user, char* password, int* res) {
	strncpy(buffer, password, sizeof(char) * (strlen(password)+1));
	if( strcmp(user, "guy") == 0  &&  strcmp(buffer, CORRECT_PASS_GUY) == 0 ) {
		pass = 1;
	} else if (strcmp(user, "bassam") == 0   &&  strcmp(buffer, CORRECT_PASS_BASSAM) == 0) {
		pass = 1;
	} else {
		memcpy(res, &FAIL, sizeof(FAIL));
	}

	if (pass != 0) {
		memcpy(res, &SUCCESS, sizeof(SUCCESS));
	} else {
		memcpy(res, &FAIL, sizeof(FAIL));
	}
}
