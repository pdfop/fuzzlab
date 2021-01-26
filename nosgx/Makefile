CC := afl-gcc-fast 
CXX := afl-g++-fast
AFL_CC := gcc 
AFL_CXX := g++


SGX_COMMON_CFLAGS := -m64 -O0 -g -DDEBUG -UNDEBUG -UEDEBUG
App_Cpp_Files := App/App.cpp
App_Include_Paths := -IInclude -IApp
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -lpthread


all:
	@$(CXX) -o app ${App_Link_Flags} $(App_Cpp_Flags) ./App.cpp

clean:
	@rm -f ./app 
