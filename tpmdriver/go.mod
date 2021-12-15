module tpmdriver

go 1.17

require (
	attestationreport v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.3.2
	github.com/sirupsen/logrus v1.8.1
	ima v0.0.0-00010101000000-000000000000
)

require (
	github.com/Fraunhofer-AISEC/go-attestation v0.3.3-0.20211213210926-83c4ce2d4733 // indirect
	github.com/google/certificate-transparency-go v1.1.1 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace attestationreport => ../attestationreport

replace ima => ../ima
