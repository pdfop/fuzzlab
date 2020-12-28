// warning here propagates from warning in App.h, will be resolved at build time 
#include "App.h"
 
void ocall_print_string(const char *str);
std::vector<std::string> splitInput(std::string input); 

// CDECL macro defines calling convention 
int SGX_CDECL main(int argc, char *argv[])
{
    printf("Input: \n");
    // buffer for the input string
    char input[BUFSIZ]; 
    // reading from stdin into the buffer 
    std::cin >> input;   
    // splittin input string on whitespace
    std::string inputString(input);
    std::vector<std::string> tokens = splitInput(inputString); 
    // if the fuzzer deleted a space the vector won't have enough elements to provide values for all parameters
    if(tokens.size() < 4)
    {
        while(tokens.size()!= 4)
        {
            tokens.push_back("1234"); 
        }
    }
    // ##### SDK AREA #### 

    // all function signatures are according to their definition in the SGX Developer Reference 
    // https://download.01.org/intel-sgx/sgx-linux/2.12/docs/Intel_SGX_Developer_Reference_Linux_2.12_Open_Source.pdf
    // interface and function specifications start at page 111 

    // setting various parameters based on the fuzzer input 

    //controllable inputs 
    sgx_launch_token_t token = {stoi(tokens[0])}; 
    int updated = stoi(tokens[1]);
    const uint8_t *revokeList = reinterpret_cast<const uint8_t*>(tokens[2].data());
    uint32_t listSize = stoi(tokens[3]); 
    // set by calc_quote_size but can be changed when passed as input to get_qu
    uint32_t quoteSize = stoi(tokens[4]); 
    //sgx_quote_sign_type_t linkFlag; 
    //const sgx_spid_t servicdeId; 
    //const sgx_quote_nonce_t nonce; 
    //const uint8_t revokeListDiff[]; 
    //uint32_t listSizeDiff; 

    // pointers used as function outputs 

    sgx_enclave_id_t global_eid = 0;
    //status variable that will be used to hold return value of the last SDK call 
    sgx_status_t status;
    sgx_target_info_t target; 
    sgx_epid_group_id_t gid; 
    sgx_report_t report; 
    sgx_report_t qeReport; 

    // creating an enclave 

    /* const char* file name of the enclave - not variable as it is set during build process 
       int Debug Flag 0 or 1 - usually set by SGX_DEBUG_FLAG based on build mode 
       sgx_launch_token_t* pointer to launch token - deprecated according to SDR
            token seems to be set by aesmd.service now, will still attempt to pass input here 
       int indicator for launch token update 0 or 1 - deprecated according to SDR
       sgx_enclave_id_t* pointer to enclave id - set by function 
       sgx_misc_attribute_t* pointer to various information about the enclaves and its SECS - set by function, optional 
    */ 
    status = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL); 
    printf("Enclave successfully initilised.\n");
    // making a basic ecall which will be followed by a basic ocall by the enclave 
    ecall_echo(global_eid, input);

    // quoting process 

    /* 
        sgx_target_info_t* pointer to the target info that will be used in the report - set by function 
        sgx_epid_group_id_t* pointer to the EPID of the system - set by function
    */
   // status = sgx_init_quote(&target, &gid);

    /*
        const uint8_t* revoke list of signatures, NULL if none are revoked 
        uint32_t size of the revoke list in bytes, expected to be 0 if list is NULL 
            there is probably some room to fuzz these two 
        uint32_t* pointer to the quote size - set by function
    */
   // status = sgx_calc_quote_size(revokeList, listSize, &quoteSize);

    /*
        deprecated function 
        used to fulfill the role of calc_quote_size 
        doesn't take the second parameter from above 
        probably interesting to fuzz if it doesn't verify the buffer size of the revoke list? 
    */
   // status = sgx_get_quote_size(revokeList, &quoteSize);

    /*
        const sgx_report_t* pointer to the report that will be quoted 
        sgx_quote_sign_type_t   flag for linkable or unlinkable quote, intended values SGX_UNLINKABLE_SIGNATURE and SGX_LINKABLE_SIGNATURE
        const sgx_spid_t* service provider id 
        const sgx_quote_nonce_t* optional nonce, linked to sgx_report_t* - if one is NULL the other has be to NULL as well 
        const uint8_t* optional revoke list of signatures 
        uint32_t    size of the revoke list in bytes, should again be 0 if list is NULL
        sgx_report_t* pointer to the QE report used for this quote, optional output - set by function, expects nonce not to be NULL if this is not NULL 
        sgx_quote_t* pointer to the main quote output - set by function 
        uint32_t quote buffer size, expects the value that can be calculate by passing the size revoke list to sgx_calc_quote_size 
            probably also interesting to fuzz 
    */
    //status = sgx_get_quote(*report, linkFlag, *servicdeId, *nonce, *revokeListDiff, listSizeDiff, *qeReport, quoteSize);
    
    // destroying enclave 
    sgx_status_t enclave_status = sgx_destroy_enclave(global_eid);
    printf("\nEnclave Destroyed\n"); 
}

/*
    basic ocall
*/
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

std::vector<std::string> splitInput(std::string input)
{
    std::vector<std::string> tokens; 
    std::string buffer; 
    std::stringstream stream(input); 

    while(stream >> buffer)
    {
        tokens.push_back(buffer);
    }
    return tokens; 
}
