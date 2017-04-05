#include "stdafx.h"
#include "stdafx.h"
#include "sgx_urts.h"
#include "Enclave_libraryCalls_u.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#define ENCLAVE_FILE _T("Enclave_libraryCalls.signed.dll")

#define NO_ENCLAVE

const long long ITERATIONS = 1000000;
#ifdef NO_ENCLAVE
/* Global arrays to be used in library calls calculations */
static char* dictionary[] = { "Because","you're","a","helpful","counselor,","you","decide","to",
	"upgrade","the","traditional","system","from","notes","secretly","kept",
	"in","various","places","to","something","using","Erlang.",
	"At","first","you","figure","using","ETS","and","DETS","tables","will","be",
	"perfect.","However,","when","you're","out","on","an","overseas","trip","away","from",
	"the","boss,","it","becomes","somewhat","difficult","to","keep","things","synchronized.",
	"You","could","write","a","complex","layer","on","top","of","your","ETS","and","DETS",
	"tables","to","keep","everything","in","check.","You","could","do","that,","but","being",
	"human,","you","know","you","would","make","mistakes","and","write","buggy","software.",
	"Such","mistakes","are","to","be","avoided","when","friendship","is","so","important,",
	"so","you","look","online","to","find","how","to","make","sure","your","system","works","right.",
	"This","is","when","you","start","reading","this","chapter,","explaining","Mnesia,",
	"an","Erlang","distributed","database","built","to","solve","such","problems.", "Mnesia",
	"is","a","layer","built","on","top","of","ETS","and","DETS","to","add","a","lot","of",
	"functionality","to","these","two","databases.","It","mostly","contains","things","many",
	"developers","might","end","up","writing","on","their","own","if","they","were","to","use",
	"them","intensively.","Features","include","the","ability","to","write","to","both","ETS",
	"and","DETS","automatically,","to","both","have","DETS'","persistence","and","ETS'",
	"performance,","or","having","the","possibility","to","replicate","the","database",
	"to","many","different","Erlang","nodes","automatically." };

static int baseArr[] = {12,65,87,1,34,65,98,80,44,6,
	3,67,34,12,54,67,65,1,4,88,13,
	23,34,65,76,34,32,34,64,8,4,2,5,
	8,9,4,2,2,4,23,54,46,23,4,54};
#endif 
				
#ifdef ENCLAVE								
sgx_status_t createEnclave(sgx_enclave_id_t *eid) {
	sgx_status_t		ret   = SGX_SUCCESS;
	sgx_launch_token_t	token = {0};
	int					updated = 0;	
	// Create the Enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	return ret;
}
#endif

#ifdef NO_ENCLAVE
void libraryCalls_NoEnclave() {
	char* max_str(dictionary[0]), *max_len(dictionary[0]);
	size_t len = sizeof(dictionary) / sizeof(dictionary[0]);
	for (unsigned int i(1); i < len; ++i) {
	   max_str = strcmp(max_str, dictionary[i]) > 0 ? max_str : dictionary[i];	   
	   max_len = strlen(max_len) > strlen(dictionary[i]) ? max_len : dictionary[i];	   
	}	
	long long int acc(1);
	for(size_t i = 0; i < (sizeof(baseArr)/sizeof(baseArr[0])); i++) {
		baseArr[i]=sqrt(pow((double)baseArr[i],2.0));
		acc += i * baseArr[i] + rand();
	}
}
#endif

int _tmain(int argc, _TCHAR* argv[])
{
#ifdef ENCLAVE
	/* Creating Enclave */
	sgx_enclave_id_t	eid;
	if (createEnclave(&eid) != SGX_SUCCESS) {
		printf("App: error-, failed to create enclave.\n");
		return -1;
	} else {
		printf("Enclave created!\n");
	}	
	/* calling the Enclave's function */
	printf("[Enclave]");
	for(long long i(0); i < ITERATIONS; ++i) {
		libraryCalls_Enclave(eid);
	}
#endif
	
#ifdef NO_ENCLAVE
	printf("[No Enclave]");
	/* calling function without Enclave */
	for(long long i(0); i < ITERATIONS; ++i) {
		libraryCalls_NoEnclave();
	}
#endif
	return 0;
}

