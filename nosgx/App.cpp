#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
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
void ecall_echo(const char *str);
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
        // assert vector has enough elements even when fuzzer deletes spaces 
        while(tokens.size() < 4)
        {
            tokens.push_back("1234"); 
        }

        // process input based on target functions 
        const char* secret = tokens[0].c_str();
        const char* fileIdentifier = tokens[1].c_str();
        struct simpleStruct simple; 
        simple.name = (char*) tokens[2].c_str();
        simple.number = stoi(tokens[3]); 
        int numbers[tokens.size() - 3];
        for(int i = 0; i + 3 < tokens.size(); i++)
        {
            numbers[i] = stoi(tokens[i+3]); 
        }

        // call target functions
        ecall_echo((char*)buf);
        ecall_input_dependent_accesses(secret, strlen(secret)); 
        ecall_file_handling(fileIdentifier, strlen(fileIdentifier)); 
        ecall_math( numbers, sizeof(numbers)); 
        ecall_custom_input(&simple);  
    }

}

// I/O processing function 
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

// all app and enclave functions as implemented in the sgx project 
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void print_string(const char *str, ...)
{
    char buffer[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, str);
    vsnprintf(buffer, BUFSIZ, str, ap);
    va_end(ap);
    ocall_print_string(buffer);
}

void ecall_echo(const char* str)
{
    char buffer[BUFSIZ] = "echo "; 
    strncat(buffer,str, BUFSIZ-6); 
    print_string(buffer);

}

void ecall_input_dependent_accesses(const char* secret, size_t len)
{
    int a = 5; 
    int b = 3; 
    int x = 21314;
    int y = 32224; 

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
        sum += numbers[i]; 
        product *= numbers[i]; 
    }
}

void ecall_custom_input(struct simpleStruct* simple )
{
    const char* name = simple->name; 
    int number = simple->number; 
    int x = number + 10; 
    simple->number = x; 
}
