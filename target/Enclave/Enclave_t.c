#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_echo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_echo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_echo_t* ms = SGX_CAST(ms_ecall_echo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_str = ms->ms_str;
	size_t _len_str = ms->ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_echo((const char*)_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_input_dependent_accesses(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_input_dependent_accesses_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_input_dependent_accesses_t* ms = SGX_CAST(ms_ecall_input_dependent_accesses_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_secret = ms->ms_secret;
	size_t _len_secret = ms->ms_secret_len ;
	char* _in_secret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_secret, _len_secret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_secret != NULL && _len_secret != 0) {
		_in_secret = (char*)malloc(_len_secret);
		if (_in_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_secret, _len_secret, _tmp_secret, _len_secret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_secret[_len_secret - 1] = '\0';
		if (_len_secret != strlen(_in_secret) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_input_dependent_accesses((const char*)_in_secret, ms->ms_len);

err:
	if (_in_secret) free(_in_secret);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_file_handling(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_file_handling_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_file_handling_t* ms = SGX_CAST(ms_ecall_file_handling_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_fileIdentifier = ms->ms_fileIdentifier;
	size_t _len_fileIdentifier = ms->ms_fileIdentifier_len ;
	char* _in_fileIdentifier = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fileIdentifier, _len_fileIdentifier);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fileIdentifier != NULL && _len_fileIdentifier != 0) {
		_in_fileIdentifier = (char*)malloc(_len_fileIdentifier);
		if (_in_fileIdentifier == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fileIdentifier, _len_fileIdentifier, _tmp_fileIdentifier, _len_fileIdentifier)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_fileIdentifier[_len_fileIdentifier - 1] = '\0';
		if (_len_fileIdentifier != strlen(_in_fileIdentifier) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_file_handling((const char*)_in_fileIdentifier, ms->ms_len);

err:
	if (_in_fileIdentifier) free(_in_fileIdentifier);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_math(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_math_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_math_t* ms = SGX_CAST(ms_ecall_math_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_numbers = ms->ms_numbers;
	size_t _len_numbers = sizeof(int);
	int* _in_numbers = NULL;

	CHECK_UNIQUE_POINTER(_tmp_numbers, _len_numbers);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_numbers != NULL && _len_numbers != 0) {
		if ( _len_numbers % sizeof(*_tmp_numbers) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_numbers = (int*)malloc(_len_numbers);
		if (_in_numbers == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_numbers, _len_numbers, _tmp_numbers, _len_numbers)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_math(_in_numbers, ms->ms_len);

err:
	if (_in_numbers) free(_in_numbers);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_custom_input(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_custom_input_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_custom_input_t* ms = SGX_CAST(ms_ecall_custom_input_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct simpleStruct* _tmp_simple = ms->ms_simple;
	size_t _len_simple = sizeof(struct simpleStruct);
	struct simpleStruct* _in_simple = NULL;

	CHECK_UNIQUE_POINTER(_tmp_simple, _len_simple);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_simple != NULL && _len_simple != 0) {
		_in_simple = (struct simpleStruct*)malloc(_len_simple);
		if (_in_simple == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_simple, _len_simple, _tmp_simple, _len_simple)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_custom_input(_in_simple);

err:
	if (_in_simple) free(_in_simple);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_echo, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_input_dependent_accesses, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_file_handling, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_math, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_custom_input, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][5];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

