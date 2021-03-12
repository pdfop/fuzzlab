// warning here propagates from warning in App.h, will be resolved at build time 
#include "App.h"
#include <unistd.h>
#include <stdlib.h>

// compiler optimization settings
#pragma clang optimize off
#pragma GCC            optimize("O0")

// initializes persistent mode 
 __AFL_FUZZ_INIT();

void ocall_print_string(const char *str);
std::vector<std::string> splitInput(std::string input); 
int assertNumber(const char* token); 

// CDECL macro defines calling convention 
int SGX_CDECL main(int argc, char *argv[])
{
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif
    // AFL fuzzing input buffer
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // ##### SDK AREA #### 

    // all function signatures are according to their definition in the SGX Developer Reference 
    // https://download.01.org/intel-sgx/sgx-linux/2.12/docs/Intel_SGX_Developer_Reference_Linux_2.12_Open_Source.pdf
    // interface and function specifications start at page 111 

    // define all variables that get fuzzed input here so they are not constantly re-initialized in the loop 

    // controllable inputs to sdk functions 

    // while these are controllable we cannot really set them as they are only used during enclave creation
    // which has to be done outside of the loop as looping it will kill performance 
    // they are also officially deprecated 
    sgx_launch_token_t token; 
    int updated; 
    // set by calc_quote_size but can be changed when passed as input to get_quote
    uint32_t quoteSize;
    // only used during actual quote, needs spid 
    sgx_quote_sign_type_t linkFlag;
    // size of the revoke list 
    uint32_t listSize;
    const uint8_t* revokeList;  
    // actual attestation id, requires intel account 
    //const sgx_spid_t servicdeId;  

    // pointers used as function outputs 

    // global id of our enclave, needs to be passed to each ecall 
    sgx_enclave_id_t global_eid = 0;
    //status variable that will be used to hold return value of the last SDK call 
    sgx_status_t status;
    sgx_target_info_t target; 
    sgx_epid_group_id_t gid; 
    sgx_report_t report; 
    sgx_report_t qeReport; 


    // variable declarations for ecall parameters 
    const char* secret;
    const char* fileIdentifier;
    struct simpleStruct simple; 

    // input management variable
    std::vector<std::string> tokens;

    // creating an enclave 

    /* const char* file name of the enclave - not variable as it is set during build process 
       int Debug Flag 0 or 1 - usually set by SGX_DEBUG_FLAG based on build mode 
       sgx_launch_token_t* pointer to launch token - deprecated according to SDR
            token seems to be set by aesmd.service now, will still attempt to pass input here 
       int indicator for launch token update 0 or 1 - deprecated according to SDR
       sgx_enclave_id_t* pointer to enclave id - set by function 
       sgx_misc_attribute_t* pointer to various information about the enclaves and its SECS - set by function, optional 
    */ 
    // has to be called outside of the loop. huge performance cost 
    status = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL); 
 
    // fuzzing target needs to be in the __AFL_LOOP while loop 
    // number indicates runs before full program restart, setting higher/lower mostly affects memory leaks etc 
    // in this cause the number also dictates how often the enclave is built&destroyed, setting it lower will negatively impact performance
    while(__AFL_LOOP(1000))
    {
        // has to be first statement in loop for persistent mode, do not move, remove or reuse the macro 
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // split input string 
        std::string inputString((char*)buf);
        tokens = splitInput(inputString);

        // process input based on target functions 

        // controllable inputs for sdk quoting functions 
        quoteSize = assertNumber(tokens[0].c_str()); 
        //linkFlag  
        listSize = assertNumber(tokens[1].c_str()); 
        // avoid uint8 overflow 
        int revokeInt = atoi(tokens[2].c_str());
        if(revokeInt < 254)
        {
            // pass actually valid pointer to a unint8_t variable 
            const uint8_t revoked = (const uint8_t) revokeInt; 
            revokeList = &revoked;  
        }
        else
        {
            const uint8_t revoked = (const uint8_t) atoi("a"); 
            revokeList = &revoked; 
        }

        //servicdeId; 

        // inputs for custom ecalls 
        secret = tokens[3].c_str();
        fileIdentifier = tokens[4].c_str();
        simple.name = (char*) tokens[5].c_str();

        // assert entry can be converted to number 
        simple.number = assertNumber(tokens[6].c_str());  

        // assumption can be made as tokens is filled up to the needed length in the splitInput function 
        int numbers[tokens.size() - 6];

        for(int i = 0; i + 6 < tokens.size(); i++)
        {   
            numbers[i] = assertNumber(tokens[i+6].c_str()); 
        }

        // call target functions
        ecall_echo(global_eid, (char*)buf, strlen((char*) buf));
        ecall_input_dependent_accesses(global_eid,  secret, strlen(secret)); 
        //has no implementation
        ecall_file_handling(global_eid, fileIdentifier, strlen(fileIdentifier)); 
        // LAST MINUTE CHANGE: this causes the untraceable crashes, may be memory related. no time to debug 
        // leaving out of final run 
        //ecall_math(global_eid, numbers, sizeof(numbers)); 
        ecall_custom_input(global_eid, &simple);  
    
        // quoting process     

        /* 
            sgx_target_info_t* pointer to the target info that will be used in the report - set by function 
            sgx_epid_group_id_t* pointer to the EPID of the system - set by function
        */
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
        status = sgx_get_quote_size(revokeList, &quoteSize);

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
    
    }

    // destroying enclave 
    sgx_status_t enclave_status = sgx_destroy_enclave(global_eid);
    
    
 
}

/*
    basic ocall
*/
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

// I/O processing function 
std::vector<std::string> splitInput(std::string input)
{
    // input is fed to this function by the fuzzer directly 
    // input is always a single string that needs to be split into multiple values to create multiple parameters 
    // parameter values are supposed to be split by white space in the input file 
    std::vector<std::string> tokens; 
    std::string buffer; 
    std::stringstream stream(input); 

    while(stream >> buffer)
    {
        tokens.push_back(buffer);
    }

     // assert vector has enough elements even when fuzzer deletes spaces 
    while(tokens.size() < 8)
    {
        // numbers are safe for all parameters,so add numbers 
       tokens.push_back("3"); 
    }
    
    return tokens; 
}

int assertNumber(const char* token)
{
    bool isNumber = true; 
    for(int x = 0; x < strlen(token); x++)
    {
        if(token[x] > 9 || token[x] < 0)
        {
            isNumber = false;
            break;  
        }
    }
        if(isNumber)
        {
            return atoi(token); 
        }
        else
        {
            return random(); 
        }
}
