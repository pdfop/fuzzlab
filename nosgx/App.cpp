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

// performance boost 
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
void print_string(const char *str, ...);
void ecall_echo(const char *str, size_t len);
void ecall_input_dependent_accesses(const char* secret, size_t len); 
void ecall_file_handling(const char* fileIdentifier, size_t len); 
void ecall_math(int* numbers, size_t len); 
void ecall_custom_input(struct simpleStruct* simple);

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
        std::vector<std::string> tokens = splitInput(inputString);

        // process input based on target functions 
        const char* secret = tokens[0].c_str();
        const char* fileIdentifier = tokens[1].c_str();
        struct simpleStruct simple; 
        simple.name = (char*) tokens[2].c_str();

        // assert entry can be converted to number 
        const char *token = tokens[3].c_str(); 
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
            simple.number = atoi(token); 
        }
        else
        {
            simple.number = 3; 
        }

        // assumption can be made as tokens is filled up the the needed length in the splitInput function 
        int numbers[tokens.size() - 3];

        for(int i = 0; i + 3 < tokens.size(); i++)
        {   
            token = tokens[i+3].c_str(); 
            isNumber = true; 
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
                numbers[i] = atoi(token); 
            }
            else
            {
                numbers[i] = 1; 
            }
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
    while(tokens.size() < 4)
    {
        // numbers are safe for all parameters,so add numbers 
       tokens.push_back("1234"); 
    }
    
    return tokens; 
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
