module cmcd

go 1.17

require (
	attestationreport v0.0.0-00010101000000-000000000000
	cmcinterface v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	google.golang.org/grpc v1.42.0
	gopkg.in/square/go-jose.v2 v2.6.0
	tpmdriver v0.0.0-00010101000000-000000000000
)

require (
	github.com/Fraunhofer-AISEC/go-attestation v0.3.3-0.20211213210926-83c4ce2d4733 // indirect
	ima v0.0.0-00010101000000-000000000000 // indirect
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/certificate-transparency-go v1.1.1 // indirect
	github.com/google/go-tpm v0.3.2 // indirect
	github.com/google/go-tspi v0.2.1-0.20190423175329-115dea689aad // indirect
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20211113001501-0c823b97ae02 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20211115160612-a5da7257a6f7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	provclient v0.0.0-00010101000000-000000000000
)

replace attestationreport => ../attestationreport

replace ima => ../ima

replace provclient => ../provclient

replace cmcinterface => ../cmcinterface

replace tpmdriver => ../tpmdriver
