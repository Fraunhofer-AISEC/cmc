module testclient

go 1.17

replace attestationreport => ../attestationreport

require (
	cmcinterface v0.0.0-00010101000000-000000000000
	connectorlibrary v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	google.golang.org/grpc v1.42.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20211113001501-0c823b97ae02 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20211112145013-271947fe86fd // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace connectorlibrary => ../connectorlibrary

replace cmcinterface => ../cmcinterface
