#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _simpleStruct
#define _simpleStruct
typedef struct simpleStruct {
	char* name;
	int number;
} simpleStruct;
#endif

void ecall_echo(const char* str, size_t len);
void ecall_input_dependent_accesses(const char* secret, size_t len);
void ecall_file_handling(const char* fileIdentifier, size_t len);
void ecall_math(int* numbers, size_t len);
void ecall_custom_input(struct simpleStruct* simple);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
