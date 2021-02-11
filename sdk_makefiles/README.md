buildenv.mk and Makefile.root as Makefile in the root linux-sgx folder  
Makefile.root.sdk as Makefile and Makefile.source.root.sdk as Makefile.source in linux-sgx/sdk   
Makefile.root.sdk.selib.linux as Makefile in linux-sgx/sdk/selib/linux   


requires afl-gcc-fast, afl-g++-fast, gcc and g++ to be in path. verify with 'which <program>'  
does not instrument pthread, ptrace, trts, the custom sgx libc and any other trusted components  
instruments all untrusted components, verify instrumentation output during make process  
should solve any problems with missing pthread functions  
only works if enclave files are not instrumented (i.e. trying to compile the sdk examples will fail)  


from testing does not seem to deliver path information or feeback for functions beyond the urts i.e. does not get any info from ecalls. did seem get path info from urts quote functions in testing - might be false positive  

still working on modifying build process to instrument as much code as possible  

