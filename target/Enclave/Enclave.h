#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#if defined(__cplusplus)
extern "C" {
#endif

void print_string(const char *str, ...);
void ecall_echo(const char *str);

#if defined(__cplusplus)
}
#endif
#endif 