#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
// needed for afl persistent mode 
#include <unistd.h>

#include "/opt/intel/sgxsdk/include/sgx_urts.h"


#include "/opt/intel/sgxsdk/include/sgx_error.h"       // sgx_status_t 
#include "/opt/intel/sgxsdk/include/sgx_eid.h"     // sgx_enclave_id_t 
#include "/opt/intel/sgxsdk/include/sgx_uae_epid.h" // quoting process

// compiler optimization setting 
#pragma clang optimize off
#pragma GCC            optimize("O0")

// persistent mode initialization 
__AFL_FUZZ_INIT();

// structs to pass custom data formats to ecalls 
struct simpleStruct
{
    char* name; 
    int number; 
}; 

// prototypes as used in the sgx project 
void ocall_print_string(const char *str);
std::vector<std::string> splitInput(std::string input); 
int assertNumber(const char* token);
void print_string(const char *str, ...);
void ecall_echo(const char *str, size_t len);
void ecall_input_dependent_accesses(const char* secret, size_t len); 
void ecall_file_handling(const char* fileIdentifier, size_t len); 
void ecall_math(int* numbers, size_t len); 
void ecall_custom_input(struct simpleStruct* simple);


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


int main(int argc, char *argv[])
{
    // persistent mode setup 
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif
    // fuzzing input buffer 
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    // number indicates runs before full program restart, setting higher/lower mostly affects memory leaks etc 
    // in the sgx version this affects how often the enclave is built/destroyed, higher value will run faster 
    while(__AFL_LOOP(10000))
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
        ecall_echo((char*)buf, strlen((char*) buf));
        ecall_input_dependent_accesses(secret, strlen(secret)); 
        //ecall_file_handling(fileIdentifier, strlen(fileIdentifier)); 
        ecall_math(numbers, sizeof(numbers)); 
        ecall_custom_input(&simple);  
    }

}

// I/O processing function 
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

// all app and enclave functions as implemented in the sgx project 


void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void print_string(size_t len, const char *str, ...)
{
    char buffer[len];
    va_list ap;
    va_start(ap, str);
    vsnprintf(buffer, len, str, ap);
    va_end(ap);
    ocall_print_string(buffer);
}

void ecall_echo(const char* str, size_t len)
{
    const char* echo = "echo "; 
    int bufsiz = len + strlen(echo);
    char buffer[bufsiz];
    for(int i = 0; i<strlen(echo); i++)
    {
        buffer[i] = echo[i]; 
    }
    strncat(buffer,str, len); 
   ocall_print_string(buffer);
}

void ecall_input_dependent_accesses(const char* secret, size_t len)
{
    int a = 5; 
    int b = 3; 
    int x = 2134;
    int y = 3224; 
    // assert secret is long enough to make the accesses below 
    if(len < 5)
    {
        return; 
    }
    if(secret[0] == 'a')
    {
        if(secret[3] == 'x')
        {
            if(secret[5] == 'y')
            {
                int res = a + x * y; 
            }
        }
    }
    
    if(secret[0] == 'b')
    {
        if(secret[1] == 'a')
        {
            if(secret[2] == 'c')
            {
                int res2 = b + x; 
            }
        }
    }
}

void ecall_file_handling(const char* fileIdentifier, size_t len)
{

}

void ecall_math(int* numbers, size_t len)
{
    int sum; 
    int product; 
    for(int i = 0; i < len; i++)
    {
        int x = numbers[i]; 
        // check for overflows and underflows in the operations 
        // addtion 
        if (x > 0 && sum > INT_MAX - x)
        {
         continue;   
        }
        if (x < 0 && sum < INT_MIN -x)
        {
            continue; 
        }
        
        // multiplication
        if (x != 0 && product > INT_MAX / x)
        {
            continue; 
        }
        if (x != 0 && product < INT_MIN / x)
        {
            continue; 
        }
        sum += x; 
        product *= x; 
    }
}

void ecall_custom_input(struct simpleStruct* simple )
{
    const char* name = simple->name; 
    int number = simple->number; 
    // check for overflow in the addition below
    if ((number > 0) && (number> INT_MAX - 10))
    {
        return;   
    }
    int x = number + 10; 
    simple->number = x; 
}

