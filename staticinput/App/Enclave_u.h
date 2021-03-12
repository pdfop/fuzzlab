#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


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

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_echo(sgx_enclave_id_t eid, const char* str, size_t len);
sgx_status_t ecall_input_dependent_accesses(sgx_enclave_id_t eid, const char* secret, size_t len);
sgx_status_t ecall_file_handling(sgx_enclave_id_t eid, const char* fileIdentifier, size_t len);
sgx_status_t ecall_math(sgx_enclave_id_t eid, int* numbers, size_t len);
sgx_status_t ecall_custom_input(sgx_enclave_id_t eid, struct simpleStruct* simple);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
