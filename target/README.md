Host App files in App    
Enclave files in Enclave    
Enclave.edl defines the ECALL/OCALL interface available for the enclave     
Enclave.config.xml manages parameters such as stack size, heap size and maximum number of threads     
Enclave_private key pair is used during initialization     
Enclave.lds honestly no idea what it does, it is needed and included in all the example projects I could find as well as in the SDK buildscripts directory     



Not supporting SIM mode in the make file     
Only available targets are make clean and make (all)     



adding additional SDK calls might require additional libraries   
add libaries to App_Link_Flags in the Makefile  
compiler set in the Makefile   
feel free to try any compiler but this is made for gcc/g++   
secondary compiler definitions to gcc and g++ are needed to exclude enclave   



Fuzzer seeds in ./in/inputs    
input format depends on which parameters you are setting based on input   
parameters in the input string are always separated by space   
afl-fuzz -i in -o out ./app    



Troubleshooting: 
Library not found e.g. /usr/bin/ld libsgx_uae_service.so not found  
	library might be part of the SDK and found at /opt/intel/sgxsdk/lib64 
	including that path might cause

Please use the PSW library  
	some libraries exist as SDK and PSW version   
	if you -L/opt/intel/sgxsdk/lib64  or set LD_LIBRARY_PATH your loader might find and use these   
	you want to use the PSW libraries at /usr/lib/x86_64-linux-gnu   
	LD_LIBRARY_PATH searches directories in order so :/usr/lib/x86_64-linux-gnu:/opt/intel/sgxsdk/lib64 fixes this

Library sgx_epid.so not found // use PSW version of EPID library 
	another one that exists as a SDK and PSW library   
	however on my system the PSW installed it as libsgx_epid.so.1 which gets skipped in favour of the SDK one   
	symlink fixes this   
	ln -s libsgx_epid.so.1 libsgx_epid.so in /usr/lib/x86_64-linux-gnu   
