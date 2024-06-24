package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/verify"
)

var (
	pckCertUrl = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert?encrypted_ppid=%s&cpusvn=%s&pceid=%s&pcesvn=%s"
)

func main() {
	encrypted_ppid := flag.String("encrypted_ppid", "", "Encrypted PPID string")
	pceid := flag.String("pceid", "", "PCEID string")
	cpusvn := flag.String("cpusvn", "", "CPUSVN string")
	pcesvn := flag.String("pcesvn", "", "PCESVN string")
	flag.Parse()

	if encrypted_ppid == nil || pceid == nil || cpusvn == nil || pcesvn == nil {
		return
	}

	pckCertUrl = fmt.Sprintf(pckCertUrl, *encrypted_ppid, *cpusvn, *pceid, *pcesvn)

	resp, err := http.Get(pckCertUrl)
	if err != nil {
		fmt.Println("failed to retrieve PCK certificate")
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("failed to read response body")
		return
	}

	cert, err := internal.ParseCertsPem(body)
	if err != nil {
		fmt.Println("failed to parse PEM certificate")
		return
	}

	sgxExtensions, err := verify.ParseSGXExtensions(cert[0].Extensions[verify.SGX_EXTENSION_INDEX].Value[4:])
	if err != nil {
		fmt.Println("failed to parse SGX extensions")
		return
	}
	fmt.Print(hex.EncodeToString(sgxExtensions.Fmspc.Value))
}
