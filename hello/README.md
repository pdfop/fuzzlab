simple Hello World enclave project to verify working SGX installation   
accepts command line input and prints "hello <input>"  


trouble shooting: 

"failed to load enclave"    
verify PSW installation and aesmd status    
run sudo service aesmd status  
if "QE load failed" run sudo service aesmd restart    
if "aesmd.service not found" your PSW installation is faulty  

"invalid sgx device. enable sgx in bios then install the driver"  
verify that the driver kernel module is loaded  
run lsmod | grep "isgx"  
if this does not show anything try running sudo /sbin/modprobe isgx or reinstall driver    
make sure to use this driver https://github.com/intel/linux-sgx-driver and follow instructions  
might require a system / aesmd.service restart after reinstalling driver 





