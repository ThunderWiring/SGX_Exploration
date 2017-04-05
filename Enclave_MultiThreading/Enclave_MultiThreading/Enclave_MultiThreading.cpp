/*
 * Implementing Readers-Writers
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "Enclave_MultiThreading_t.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include <sgx_thread.h>	

#define READ_IN   "                         read_in"
#define READ_OUT  "                               read_out"
#define WRITE_IN  "write_in"
#define WRITE_OUT "      write_out"

static int number_of_readers = 0; 
static sgx_thread_cond_t readers_condition = SGX_THREAD_COND_INITIALIZER;
static int number_of_writers = 0;
static sgx_thread_cond_t writers_condition = SGX_THREAD_COND_INITIALIZER;
static sgx_thread_mutex_t global_lock = SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER;

static void readers_writers_init() {
	number_of_readers = 0;
	sgx_thread_cond_init(&readers_condition, NULL);
	number_of_writers = 0;
	sgx_thread_cond_init(&writers_condition, NULL);
	sgx_thread_mutex_init(&global_lock, NULL);
	sgx_thread_mutex_lock(&global_lock);
	sgx_thread_mutex_lock(&global_lock);
}

static void read_lock() {
	sgx_thread_mutex_lock(&global_lock);
	while(number_of_writers > 0) {
		sgx_thread_cond_wait(&readers_condition, &global_lock);
	}
	number_of_readers++;
	int* tmp = (int*) malloc(sizeof(int));
	memcpy(tmp, &number_of_readers, sizeof(int));
	sgx_thread_mutex_unlock(&global_lock);
}

static void read_unlock() {
	sgx_thread_mutex_lock(&global_lock);
	number_of_readers--;
	if(number_of_readers == 0) {
		sgx_thread_cond_signal(&writers_condition);
	}
	sgx_thread_mutex_unlock(&global_lock);
}

static void writers_lock() {
	sgx_thread_mutex_lock(&global_lock);
	while(number_of_writers > 0 || number_of_readers > 0) {
		sgx_thread_cond_wait(&writers_condition, &global_lock);
	}
	number_of_writers++;
	sgx_thread_mutex_unlock(&global_lock);
}

static void writers_unlock() {
	sgx_thread_mutex_lock(&global_lock);
	number_of_writers--;
	if(number_of_writers == 0) {
		sgx_thread_cond_broadcast(&readers_condition);
		sgx_thread_cond_signal(&writers_condition);
	}
	sgx_thread_mutex_unlock(&global_lock);
}
/************************/
/*      Enclave API		*/
/************************/
void Enclave_Init() {
	Ocall_printf("   [Enclave] - Initialized.\n", NULL);
	readers_writers_init();
}

void Enclave_Read(int* thread_id, size_t len) {
	read_lock();
	int* tmp = (int*) malloc(sizeof(int));
	memcpy(tmp, thread_id, sizeof(int));
	Ocall_printf(READ_IN , tmp);
	read_unlock();
	Ocall_printf(READ_OUT , tmp);
}

void Enclave_Write(int* thread_id, size_t len) {
	writers_lock();
	int* tmp = (int*) malloc(sizeof(int));
	memcpy(tmp, thread_id, sizeof(int));
	Ocall_printf(WRITE_IN, tmp);
	writers_unlock();
	Ocall_printf(WRITE_OUT, tmp);
}