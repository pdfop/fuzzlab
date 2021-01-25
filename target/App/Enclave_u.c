#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_echo_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_echo_t;

typedef struct ms_ecall_input_dependent_accesses_t {
	const char* ms_secret;
	size_t ms_secret_len;
	size_t ms_len;
} ms_ecall_input_dependent_accesses_t;

typedef struct ms_ecall_file_handling_t {
	const char* ms_fileIdentifier;
	size_t ms_fileIdentifier_len;
	size_t ms_len;
} ms_ecall_file_handling_t;

typedef struct ms_ecall_math_t {
	int* ms_numbers;
	size_t ms_len;
} ms_ecall_math_t;

typedef struct ms_ecall_custom_input_t {
	struct simpleStruct* ms_simple;
} ms_ecall_custom_input_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t ecall_echo(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_echo_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_input_dependent_accesses(sgx_enclave_id_t eid, const char* secret, size_t len)
{
	sgx_status_t status;
	ms_ecall_input_dependent_accesses_t ms;
	ms.ms_secret = secret;
	ms.ms_secret_len = secret ? strlen(secret) + 1 : 0;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_file_handling(sgx_enclave_id_t eid, const char* fileIdentifier, size_t len)
{
	sgx_status_t status;
	ms_ecall_file_handling_t ms;
	ms.ms_fileIdentifier = fileIdentifier;
	ms.ms_fileIdentifier_len = fileIdentifier ? strlen(fileIdentifier) + 1 : 0;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_math(sgx_enclave_id_t eid, int* numbers, size_t len)
{
	sgx_status_t status;
	ms_ecall_math_t ms;
	ms.ms_numbers = numbers;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_custom_input(sgx_enclave_id_t eid, struct simpleStruct* simple)
{
	sgx_status_t status;
	ms_ecall_custom_input_t ms;
	ms.ms_simple = simple;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

