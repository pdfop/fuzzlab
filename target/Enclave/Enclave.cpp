#include "Enclave.h"
// ignore the warning, it will resolve during build time as the file is generated
#include "Enclave_t.h"

#include "/opt/intel/sgxsdk/include/sgx_trts.h"
#include <iostream>
#include <stdarg.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>



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