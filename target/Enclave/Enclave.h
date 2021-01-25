#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "stddef.h"

void print_string(const char *str, ...);
void ecall_echo(const char *str);
void ecall_input_dependent_accesses(const char* secret, size_t len); 
void ecall_file_handling(const char* fileIdentifier, size_t len); 
void ecall_math(int* numbers, size_t len); 
void ecall_custom_input(struct simpleStruct* simple); 
#if defined(__cplusplus)
}
#endif
#endif 