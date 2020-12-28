Host App files in App 
Enclave files in Enclave 
Enclave.edl defines the ECALL/OCALL interface available for the enclave 
Enclave.config.xml manages parameters such as stack size, heap size and maximum number of threads 
Enclave_private key pair is used during initialization 
Enclave.lds honestly no idea what it does, it is needed and included in all the example projects I could find as well as in the SDK buildscripts directory 

Not supporting SIM mode in the make file 
Only available targets are make clean and make (all)

Compiler set in the makefile
Fuzzer seeds in ./in/inputs 
afl-fuzz -i in -o out ./app 