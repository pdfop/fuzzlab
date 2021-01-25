#include "Enclave.h"
// ignore the warning, it will resolve during build time as the file is generated
#include "Enclave_t.h"

#include "/opt/intel/sgxsdk/include/sgx_trts.h"
#include <iostream>
#include <stdarg.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <string.h>

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
    int x = 213124121234234;
    int y = 324234234234234324; 

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