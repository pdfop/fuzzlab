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
#include <limits.h>

void ecall_echo(const char* str, size_t len)
{
   ocall_print_string(str);
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