#include "Enclave_recursive_func_t.h"

#include "sgx_trts.h"
#include "vector"
#include <algorithm>

using namespace std;
//#ifdef FACTORIAL
const int FACT_CONST = 25;
static int aux_factorial (int num) {
	if(num == 1) return num;
	return num * aux_factorial(num-1);
}
void factorial_Enclave(int* outRes, size_t size) {
	int res =  aux_factorial(FACT_CONST);
	memcpy(outRes, &res, size);
}


const int FIB_CONST= 10;
int fibo_aux(int num) {
	if(num == 1 || num == 0) return num;
	else if(num < 0) return -1;
	return fibo_aux(num-1) + fibo_aux(num-2);
}
void  fibonacci_Enclave(int* outRes, size_t size) {
	int res =  fibo_aux(FIB_CONST);
	memcpy(outRes, &res, size);
	//*outRes = res;
}
//#endif

