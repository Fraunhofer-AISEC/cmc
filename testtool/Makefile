SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib4
Enclave_Include_Paths := -I$(SGX_SDK)/include 


.PHONY: all egocmc
all:
	go build

egocmc: 
	ego-go build -tags nodefaults,libapi,tpm,snp,tdx,sgx,sw && ego sign ../example-setup/enclave.json


