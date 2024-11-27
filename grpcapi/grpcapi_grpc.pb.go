// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.12.4
// source: grpcapi.proto

package grpcapi

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CMCServiceClient is the client API for CMCService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CMCServiceClient interface {
	// Signs content of request with key that belongs to ID of requester
	TLSSign(ctx context.Context, in *TLSSignRequest, opts ...grpc.CallOption) (*TLSSignResponse, error)
	TLSCert(ctx context.Context, in *TLSCertRequest, opts ...grpc.CallOption) (*TLSCertResponse, error)
	Attest(ctx context.Context, in *AttestationRequest, opts ...grpc.CallOption) (*AttestationResponse, error)
	Verify(ctx context.Context, in *VerificationRequest, opts ...grpc.CallOption) (*VerificationResponse, error)
	PeerCache(ctx context.Context, in *PeerCacheRequest, opts ...grpc.CallOption) (*PeerCacheResponse, error)
	Measure(ctx context.Context, in *MeasureRequest, opts ...grpc.CallOption) (*MeasureResponse, error)
}

type cMCServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCMCServiceClient(cc grpc.ClientConnInterface) CMCServiceClient {
	return &cMCServiceClient{cc}
}

func (c *cMCServiceClient) TLSSign(ctx context.Context, in *TLSSignRequest, opts ...grpc.CallOption) (*TLSSignResponse, error) {
	out := new(TLSSignResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/TLSSign", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cMCServiceClient) TLSCert(ctx context.Context, in *TLSCertRequest, opts ...grpc.CallOption) (*TLSCertResponse, error) {
	out := new(TLSCertResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/TLSCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cMCServiceClient) Attest(ctx context.Context, in *AttestationRequest, opts ...grpc.CallOption) (*AttestationResponse, error) {
	out := new(AttestationResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/Attest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cMCServiceClient) Verify(ctx context.Context, in *VerificationRequest, opts ...grpc.CallOption) (*VerificationResponse, error) {
	out := new(VerificationResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/Verify", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cMCServiceClient) PeerCache(ctx context.Context, in *PeerCacheRequest, opts ...grpc.CallOption) (*PeerCacheResponse, error) {
	out := new(PeerCacheResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/PeerCache", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cMCServiceClient) Measure(ctx context.Context, in *MeasureRequest, opts ...grpc.CallOption) (*MeasureResponse, error) {
	out := new(MeasureResponse)
	err := c.cc.Invoke(ctx, "/grpcapi.CMCService/Measure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CMCServiceServer is the server API for CMCService service.
// All implementations must embed UnimplementedCMCServiceServer
// for forward compatibility
type CMCServiceServer interface {
	// Signs content of request with key that belongs to ID of requester
	TLSSign(context.Context, *TLSSignRequest) (*TLSSignResponse, error)
	TLSCert(context.Context, *TLSCertRequest) (*TLSCertResponse, error)
	Attest(context.Context, *AttestationRequest) (*AttestationResponse, error)
	Verify(context.Context, *VerificationRequest) (*VerificationResponse, error)
	PeerCache(context.Context, *PeerCacheRequest) (*PeerCacheResponse, error)
	Measure(context.Context, *MeasureRequest) (*MeasureResponse, error)
	mustEmbedUnimplementedCMCServiceServer()
}

// UnimplementedCMCServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCMCServiceServer struct {
}

func (UnimplementedCMCServiceServer) TLSSign(context.Context, *TLSSignRequest) (*TLSSignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TLSSign not implemented")
}
func (UnimplementedCMCServiceServer) TLSCert(context.Context, *TLSCertRequest) (*TLSCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TLSCert not implemented")
}
func (UnimplementedCMCServiceServer) Attest(context.Context, *AttestationRequest) (*AttestationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Attest not implemented")
}
func (UnimplementedCMCServiceServer) Verify(context.Context, *VerificationRequest) (*VerificationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Verify not implemented")
}
func (UnimplementedCMCServiceServer) PeerCache(context.Context, *PeerCacheRequest) (*PeerCacheResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PeerCache not implemented")
}
func (UnimplementedCMCServiceServer) Measure(context.Context, *MeasureRequest) (*MeasureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Measure not implemented")
}
func (UnimplementedCMCServiceServer) mustEmbedUnimplementedCMCServiceServer() {}

// UnsafeCMCServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CMCServiceServer will
// result in compilation errors.
type UnsafeCMCServiceServer interface {
	mustEmbedUnimplementedCMCServiceServer()
}

func RegisterCMCServiceServer(s grpc.ServiceRegistrar, srv CMCServiceServer) {
	s.RegisterService(&CMCService_ServiceDesc, srv)
}

func _CMCService_TLSSign_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TLSSignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).TLSSign(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/TLSSign",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).TLSSign(ctx, req.(*TLSSignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CMCService_TLSCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TLSCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).TLSCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/TLSCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).TLSCert(ctx, req.(*TLSCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CMCService_Attest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).Attest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/Attest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).Attest(ctx, req.(*AttestationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CMCService_Verify_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerificationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).Verify(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/Verify",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).Verify(ctx, req.(*VerificationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CMCService_PeerCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PeerCacheRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).PeerCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/PeerCache",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).PeerCache(ctx, req.(*PeerCacheRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CMCService_Measure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MeasureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CMCServiceServer).Measure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/grpcapi.CMCService/Measure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CMCServiceServer).Measure(ctx, req.(*MeasureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CMCService_ServiceDesc is the grpc.ServiceDesc for CMCService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CMCService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpcapi.CMCService",
	HandlerType: (*CMCServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TLSSign",
			Handler:    _CMCService_TLSSign_Handler,
		},
		{
			MethodName: "TLSCert",
			Handler:    _CMCService_TLSCert_Handler,
		},
		{
			MethodName: "Attest",
			Handler:    _CMCService_Attest_Handler,
		},
		{
			MethodName: "Verify",
			Handler:    _CMCService_Verify_Handler,
		},
		{
			MethodName: "PeerCache",
			Handler:    _CMCService_PeerCache_Handler,
		},
		{
			MethodName: "Measure",
			Handler:    _CMCService_Measure_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "grpcapi.proto",
}
