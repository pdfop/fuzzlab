// warning here propagates from warning in App.h, will be resolved at build time 
#include "App.h"
#include <unistd.h>
#include <stdlib.h>

void ocall_print_string(const char *str);
std::vector<std::string> splitInput(std::string input); 
int assertNumber(const char* token); 

// CDECL macro defines calling convention 
int SGX_CDECL main(int argc, char *argv[])
{

    sgx_launch_token_t token; 
    int updated; 
    uint32_t quoteSize;
    uint32_t listSize = 0; 
    const uint8_t* revokeList = (const uint8_t*) atoi("abc");   
    sgx_enclave_id_t global_eid = 0;
    sgx_status_t status;
    sgx_target_info_t target; 
    sgx_epid_group_id_t gid; 

    status = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL); 

    status = sgx_init_quote(&target, &gid);
    
        /*
            const uint8_t* revoke list of signatures, NULL if none are revoked 
            uint32_t size of the revoke list in bytes, expected to be 0 if list is NULL 
                there is probably some room to fuzz these two 
            uint32_t* pointer to the quote size - set by function
        */
    status = sgx_calc_quote_size(revokeList, listSize, &quoteSize);

        /*
            deprecated function 
            used to fulfill the role of calc_quote_size 
            doesn't take the second parameter from above 
            probably interesting to fuzz if it doesn't verify the buffer size of the revoke list? 
        */
    //status = sgx_get_quote_size(revokeList, &quoteSize);

    // destroying enclave 
    printf("regular exit\n"); 
    sgx_status_t enclave_status = sgx_destroy_enclave(global_eid);  
 
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}
