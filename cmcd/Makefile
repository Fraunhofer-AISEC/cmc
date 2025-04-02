all:
	go build

minimal:
	go build -ldflags="-s -w" -tags nodefaults,socket,tpm,snp,tdx,sw
