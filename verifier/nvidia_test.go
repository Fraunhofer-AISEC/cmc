// Copyright (c) 2026 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/ocsp"
)

// ---------------------------------------------------------------------------
// Test fixtures
//
// The report and certificate chain below were captured from an NVIDIA H100 NVL
// (Hopper, driver 595.71.05, VBIOS 96.00.74.00.11). They are the real bytes the
// NVML calls nvmlDeviceGetConfComputeGpuAttestationReport and
// nvmlDeviceGetConfComputeGpuCertificate return, so the signature over the
// report verifies against the leaf of the chain and every parser in spdm.go can
// be exercised without a GPU present.
// ---------------------------------------------------------------------------

// testReportB64 is a signed GPU attestation report: a 37-byte SPDM GET_MEASUREMENTS
// request followed by the MEASUREMENTS response, trailed by a 96-byte ECDSA-P384
// signature. Base64 as the driver emits it into NvidiaGPUEvidence.SignedAttestationReport.
const testReportB64 = "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" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIBMwABMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAzATMAATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"NAEzAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUBMwABMAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2ATMAATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAANwEzAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgBMwAB" +
	"MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5ATMAATAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgEzAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAADsBMwABMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8ATMAATAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPQEzAAEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4BMwABMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAA/ATMAATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAEzAAEwAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOoGtjf1rvRspUac6tTNqKbqime8xTPtsMAb9oFQ6GiZsgEG" +
	"AAgAAHQAlhEAAAAOAAQACAUAAA8ACQA4ODYAAAAAAAAQAAUAMAAAAAARAAUAMTAxMAASAAUAMDIxMAATAAIAAAADAAoANTk1Ljcx" +
	"LjA1AAQACACAAQAAAAAAAAwAAAEAAAAAAQAAAAUAAAABAAAAAQAAAAEAAAABAAAAAQAAAAAAAAABAAAAAAAAAIMAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAQAAAAEAAAABAAAAAAAAAAEAAAABAAAAAQAAAAEA" +
	"AAABAAAAAgAAAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQAEAADAAQALAAEAVRQAMAAgnOAMTs+I" +
	"euzpr54rDMl1ogT2v0v5ElyXYJjYWk7MA8Zeo0KUpyPcGwae/fuYNuQVAAEAVSIAAgABACQAAgAAAFPlnA9amw1GkA/3Oay8OT8l" +
	"C3s120kBnGuNjyu47p/Vw2AVMVEKR4wMqEVTfNtWdpWFNfatfFl3XTGUrJ9/JQE2D54STcVK4cmIODT8NV54IrFsZ7KwD5+CuQoR" +
	"m0MQmA=="

// testCertChainB64 is the device certificate chain for the same GPU, leaf first,
// PEM encoded and then base64 as the driver emits it into
// NvidiaGPUEvidence.Certificates.
const testCertChainB64 = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURlekNDQXdLZ0F3SUJBZ0lVYUphTVM3ZUN4bEh3OFhCSmw1dUNyNHF3akM4" +
	"d0NnWUlLb1pJemowRUF3TXcKWkRFYk1Ca0dBMVVFQlJNU05ERkNNekZETmtJNVFrVTJPRVF3TkRVd01Rc3dDUVlEVlFRR0V3SlZV" +
	"ekViTUJrRwpBMVVFQ2d3U1RsWkpSRWxCSUVOdmNuQnZjbUYwYVc5dU1Sc3dHUVlEVlFRRERCSkhTREV3TUNCQk1ERWdSMU5RCklF" +
	"SlNUMDB3SUJjTk1qQXhNREUzTURBd01EQXdXaGdQT1RrNU9URXlNekV5TXpVNU5UbGFNSHd4TVRBdkJnTlYKQkFVVEtEWTRPVFk0" +
	"UXpSQ1FqYzRNa00yTlRGR01FWXhOekEwT1RrM09VSTRNa0ZHT0VGQ01EaERNa1l4Q3pBSgpCZ05WQkFZVEFsVlRNUnN3R1FZRFZR" +
	"UUtEQkpPVmtsRVNVRWdRMjl5Y0c5eVlYUnBiMjR4SFRBYkJnTlZCQU1NCkZFZElNVEF3SUVFd01TQkhVMUFnUmsxRElFeEdNSFl3" +
	"RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRU56NmcKTVl3WHBIbEc1ZlJzTE15SFRSL1R1UUxDYWxPVExmbkVPcENYMmFLcmUr" +
	"ZEk2Y09qUEhRNVJoMjlEcFpuMEk1TApveE1kMzAvOXA2K2w4UmE2azVzaGRxOEQ1S1V3RjBTL3BJYzVTRnNCZVIvd1Y3YjVqb3R5" +
	"OGFlYzVhc2xvNElCCldUQ0NBVlV3RGdZRFZSMFBBUUgvQkFRREFnZUFNQjBHQTFVZERnUVdCQlNvbG94THQ0TEdVZkR4Y0VtWG00" +
	"S3YKaXJDTUx6QWZCZ05WSFNNRUdEQVdnQlRUVHAxQVlnZHFhdlFReWZadm9rampUdkpjTWpBNEJnTlZIUkVFTVRBdgpvQzBHQ2lz" +
	"R0FRUUJneHlDRWdHZ0h3d2RUbFpKUkVsQk9rZElNVEF3T2pRNFFqQXlSREZDUVRFME5UZEdRekF3CmdjZ0dCbWVCQlFVRUFRU0J2" +
	"VENCdWdJQkFUQjJNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQktheE5wYW4KMkdvaDhkbW0wemh5VzkzemZwL3pnY245ZHE5" +
	"Z3ZoTldQNmNqTlowMkZsVUJ4NkhUay9YVkg0RUNBMXh3RU5WdAo2Y3pkQm11eGxJaVJiazlEQ2llZURYdW9mUjM1ai9PdExmMUdH" +
	"dThBMThWU1NPZW05Y21jVDNlMEtqQTlCZ2xnCmhrZ0JaUU1FQWdJRU1DQ2M0QXhPejRoNjdPbXZuaXNNeVhXaUJQYS9TL2tTWEpk" +
	"Z21OaGFUc3dEeGw2alFwU24KSTl3YkJwNzkrNWcyNURBS0JnZ3Foa2pPUFFRREF3Tm5BREJrQWpCZTJ2OXg3dEJqZDE5VWNXRGhn" +
	"c3MzQ3l0LwpRSThrWGZhdmxaeG9OZXUzdWpVbjNvYmwyemVJaHFqWWxsVnlJNWNDTUVJOTZ5TGJrT3R0dkE3QU41dHJpSkk0CmtF" +
	"ODVzZFZYR0FjdlRjMno2LzM5VkxYQkRiUVJ0SE91MGg2eFM1Tlhldz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1C" +
	"RUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNVVENDQWRhZ0F3SUJBZ0lKUWJNY2E1dm1qUVJRTUFvR0NDcUdTTTQ5QkFNRE1GTXhK" +
	"ekFsQmdOVkJBTU0KSGs1V1NVUkpRU0JIU0RFd01DQlFjbTkyYVhOcGIyNWxjaUJKUTBFZ01URWJNQmtHQTFVRUNnd1NUbFpKUkVs" +
	"QgpJRU52Y25CdmNtRjBhVzl1TVFzd0NRWURWUVFHRXdKVlV6QWdGdzB5TURFd01UY3dNREF3TURCYUdBODVPVGs1Ck1USXpNVEl6" +
	"TlRrMU9Wb3daREViTUJrR0ExVUVCUk1TTkRGQ016RkROa0k1UWtVMk9FUXdORFV3TVFzd0NRWUQKVlFRR0V3SlZVekViTUJrR0Ex" +
	"VUVDZ3dTVGxaSlJFbEJJRU52Y25CdmNtRjBhVzl1TVJzd0dRWURWUVFEREJKSApTREV3TUNCQk1ERWdSMU5RSUVKU1QwMHdkakFR" +
	"QmdjcWhrak9QUUlCQmdVcmdRUUFJZ05pQUFTbXNUYVdwOWhxCklmSFpwdE00Y2x2ZDgzNmY4NEhKL1hhdllMNFRWaituSXpXZE5o" +
	"WlZBY2VoMDVQMTFSK0JBZ05jY0JEVmJlbk0KM1FacnNaU0lrVzVQUXdvbm5nMTdxSDBkK1kvenJTMzlSaHJ2QU5mRlVram5wdlhK" +
	"bkU5M3RDcWpZekJoTUE4RwpBMVVkRXdFQi93UUZNQU1CQWY4d0RnWURWUjBQQVFIL0JBUURBZ0lFTUIwR0ExVWREZ1FXQkJUVFRw" +
	"MUFZZ2RxCmF2UVF5Zlp2b2tqalR2SmNNakFmQmdOVkhTTUVHREFXZ0JRcGFNc1dMTkIzbFhLaWVSQUQ1cDY2RE13S2xEQUsKQmdn" +
	"cWhrak9QUVFEQXdOcEFEQm1BakVBb0wvdE5WSkloa05SRWg4T0dZcldmS3k5R2VKUWZXNEdYdXBtUmE1Sworald3S1FUcitLUG1a" +
	"MjJqekpVRWQ2YTBBakVBaDUySnBGSjRwcXU1YWIyZmhkRXlhMkF4WEhiUzZaam0xbm5lCktyZVM3ZmxCWEhDSk5IQWxZa3VwR09M" +
	"d0t2a2YKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ3FqQ0NBaStnQXdJ" +
	"QkFnSVFhdjV4aFBraU1zamZleVFpWVhkdVZqQUtCZ2dxaGtqT1BRUURBekE5TVI0dwpIQVlEVlFRRERCVk9Wa2xFU1VFZ1IwZ3hN" +
	"REFnU1dSbGJuUnBkSGt4R3pBWkJnTlZCQW9NRWs1V1NVUkpRU0JECmIzSndiM0poZEdsdmJqQWdGdzB5TWpBek1ERXdNREF3TURC" +
	"YUdBODVPVGs1TVRJek1USXpOVGsxT1Zvd1V6RW4KTUNVR0ExVUVBd3dlVGxaSlJFbEJJRWRJTVRBd0lGQnliM1pwYzJsdmJtVnlJ" +
	"RWxEUVNBeE1Sc3dHUVlEVlFRSwpEQkpPVmtsRVNVRWdRMjl5Y0c5eVlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVE1IWXdFQVlIS29a" +
	"SXpqMENBUVlGCks0RUVBQ0lEWWdBRXpVZFdxam4xT2xYaExmRk9LQUZUZ2hxRytRM3pGNHhnU0JiWnNVRXlXWUNDM3JLakU5Tm4K" +
	"bzg4WnBCUXg4NU9vMFBrcVAyZHdvTVZOVFFNdjVjdnk5akxhVHZTVFhad04ySFFIRTl1N3g3QklZcldpMHNHMwo1cTFJSk5TT0dP" +
	"NUxvNEhiTUlIWU1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RnWURWUjBQQVFIL0JBUURBZ0VHCk1Ed0dBMVVkSHdRMU1ETXdNYUF2" +
	"b0MyR0syaDBkSEE2THk5amNtd3VibVJwY3k1dWRtbGthV0V1WTI5dEwyTnkKYkM5c01pMW5hREV3TUM1amNtd3dOd1lJS3dZQkJR" +
	"VUhBUUVFS3pBcE1DY0dDQ3NHQVFVRkJ6QUJoaHRvZEhSdwpPaTh2YjJOemNDNXVaR2x6TG01MmFXUnBZUzVqYjIwd0hRWURWUjBP" +
	"QkJZRUZDbG95eFlzMEhlVmNxSjVFQVBtCm5yb016QXFVTUI4R0ExVWRJd1FZTUJhQUZBZENvT3NEbklCZ2U2RkJZWmxOcmlYM3dw" +
	"c2VNQW9HQ0NxR1NNNDkKQkFNREEya0FNR1lDTVFESzBCQ3I0OUROSjQ4WWg1d3UzODhiWmlmREZ4QXNpVVM0VTFmR21wSlpGaENi" +
	"T0RINgptUndjTXhwNkVPYXladVlDTVFEWUtUeU5jMkZ4V0Z1aEh0ZENFM2xzNFM3U0luZWhkRXJUWk51aEZ5bWM0WU9NCjZWbExX" +
	"VFkvQ00rcmVzampxeFE9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNp" +
	"akNDQWhDZ0F3SUJBZ0lRVENWZTNqdlFBYjgvU2p0Z1g4cUppakFLQmdncWhrak9QUVFEQXpBMU1TSXcKSUFZRFZRUUREQmxPVmts" +
	"RVNVRWdSR1YyYVdObElFbGtaVzUwYVhSNUlFTkJNUTh3RFFZRFZRUUtEQVpPVmtsRQpTVUV3SUJjTk1qSXdNVEV5TURBd01EQXdX" +
	"aGdQT1RrNU9URXlNekV5TXpVNU5UbGFNRDB4SGpBY0JnTlZCQU1NCkZVNVdTVVJKUVNCSFNERXdNQ0JKWkdWdWRHbDBlVEViTUJr" +
	"R0ExVUVDZ3dTVGxaSlJFbEJJRU52Y25CdmNtRjAKYVc5dU1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFK3BnK3REVXVJ" +
	"TGxaSUxrNXdnMjJZRUo5T2g2Ywp5UGNzdjNJdmdSV2NWNExlWksxcFRDb1FESXBsWjBFNHFzTEczRzA0cHhzYk1oeGJxa2l6OXBx" +
	"bFRWMnJ0dVZnClNtSXFuU1lrVTFqV1hzUFM5b1ZMQ0dFOFZSTGwxSnZxeU94VW80SGFNSUhYTUE4R0ExVWRFd0VCL3dRRk1BTUIK" +
	"QWY4d0RnWURWUjBQQVFIL0JBUURBZ0VHTURzR0ExVWRId1EwTURJd01LQXVvQ3lHS21oMGRIQTZMeTlqY213dQpibVJwY3k1dWRt" +
	"bGthV0V1WTI5dEwyTnliQzlzTVMxeWIyOTBMbU55YkRBM0JnZ3JCZ0VGQlFjQkFRUXJNQ2t3Ckp3WUlLd1lCQlFVSE1BR0dHMmgw" +
	"ZEhBNkx5OXZZM053TG01a2FYTXViblpwWkdsaExtTnZiVEFkQmdOVkhRNEUKRmdRVUIwS2c2d09jZ0dCN29VRmhtVTJ1SmZmQ214" +
	"NHdId1lEVlIwakJCZ3dGb0FVVjRYL2cvSmp6R1Y5YUxjNgpXL1NOU3N2N1NWOHdDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXhBUElR" +
	"aG52ZUZ4WUlyUHpCcVZpVDJJMzRTZlM0CkpHV0Zuay8xVWNkbWdKbXArN2w2ckgvQzRxeHdudFlTZ2VZcmxRSXdkalF1b2ZIbmhk" +
	"MVJMMDlPQk8zNDU2NkoKQzliWUFvc1QvODZjQ29qaUdqaExuYWw5aEpPSDBuUy9scmJhb2M1YQotLS0tLUVORCBDRVJUSUZJQ0FU" +
	"RS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDQ3pDQ0FaQ2dBd0lCQWdJUUxUWndzY29RQkJIQi9zRG9LZ1pi" +
	"VkRBS0JnZ3Foa2pPUFFRREF6QTFNU0l3CklBWURWUVFEREJsT1ZrbEVTVUVnUkdWMmFXTmxJRWxrWlc1MGFYUjVJRU5CTVE4d0RR" +
	"WURWUVFLREFaT1ZrbEUKU1VFd0lCY05NakV4TVRBMU1EQXdNREF3V2hnUE9UazVPVEV5TXpFeU16VTVOVGxhTURVeElqQWdCZ05W" +
	"QkFNTQpHVTVXU1VSSlFTQkVaWFpwWTJVZ1NXUmxiblJwZEhrZ1EwRXhEekFOQmdOVkJBb01CazVXU1VSSlFUQjJNQkFHCkJ5cUdT" +
	"TTQ5QWdFR0JTdUJCQUFpQTJJQUJBNU1GS003K0tWaVpsamJRU2xnZmt5L1JSbkVRU2NXOU5EWkY4U1gKZ0FXOTZyNnUvVmU4Wmdn" +
	"dGNZcFBpMkJTNFZGdTZLZkVJcmhONkZjSEc3V1AwNVcrb00raHhqN255QTFyMWprQgoyUnk3MFlmVGhYM0JhMXpPcnlPUCtNSjl2" +
	"YU5qTUdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCCkFmOEVCQU1DQVFZd0hRWURWUjBPQkJZRUZGZUYvNFB5WTh4" +
	"bGZXaTNPbHYwalVyTCswbGZNQjhHQTFVZEl3UVkKTUJhQUZGZUYvNFB5WTh4bGZXaTNPbHYwalVyTCswbGZNQW9HQ0NxR1NNNDlC" +
	"QU1EQTJrQU1HWUNNUUNQZUZNMwpUQVNzS1FWYVQrOFMwc085dTk3UFZHQ3BFOWQvSTQySVQ3azNVVU9MU1IvcXZKeW5WT0QxdlFL" +
	"VlhmMENNUUMrCkVZNTVXWW9EQnZzMndQQUgxR3c0TGJjd1VOOFFDZmY4YkZtVjRaeGpDUnI0V1hUTEZIQktqYmZuZUdTQld3QT0K" +
	"LS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="

const (
	// Values embedded in testReportB64, cross-checked against nvidia-smi on the
	// machine the report was captured from.
	testDriverVersion = "595.71.05"
	testVbiosVersion  = "96.00.74.00.11"
	testArchitecture  = "HOPPER"

	// testNonce is the nonce echoed by testReportB64. VerifyNvidia compares the
	// caller-supplied nonce against this value.
	testNonceHex = "eb7400a94c26b407bf5a6b6aaa029f05d1ffb464df777efbf5a624f9c4aaf17f"

	// testSignatureLen is the ECDSA-P384 signature length for Hopper, see
	// CreateGpuArchitectureData
	testSignatureLen = 96

	// testMeasurementBlocks is the number of measurement blocks in the record
	testMeasurementBlocks = 64

	// testOpaqueFields is the number of opaque data fields in the SPDM response
	testOpaqueFields = 16

	// testDeviceCaFingerprint is the SHA-256 fingerprint of "NVIDIA Device Identity CA",
	// the self-signed root the device chain in testCertChainB64 ends in.
	testDeviceCaFingerprint = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"

	// testRimCaFingerprint is the SHA-256 fingerprint of "NVIDIA CoRIM signing Root CA",
	// the self-signed root embedded in the XML signature of the driver and VBIOS RIMs
	testRimCaFingerprint = "12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1"
)

// testDeviceUUID is the NVML UUID of the GPU the report was captured from. It is
// only used as the lookup key into NvidiaCollateral.OcspResponsesDeviceCerts;
// VerifyDeviceCerts does not currently cross-check it against the leaf SAN,
// which reads NVIDIA:GH100:48B02D1BA1457FC0
const testDeviceUUID = "GPU-a0b31a02-c951-1e1c-774a-a690e5de1f37"

// testTime pins the clock for certificate, RIM and OCSP validity checks. The
// device chain above is valid until 9999, but OCSP responses and RIM signing
// certificates are short lived, so tests that touch them must not use the wall
// clock. See sgx_test.go / tdx_test.go for the same pattern.
var testTime = time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Missing fixtures
//
// The following collateral could not be captured together with the report and is
// therefore left empty. Tests that need it skip themselves rather than assert on
// half a fixture. To fill these in, run the NVIDIA driver on the attesting host
// and dump what fetch_nvidia_collateral produced:
//
//   driver RIM  : GET https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GH100_595.71.05
//   VBIOS RIM   : GET https://rim.attestation.nvidia.com/v1/rim/NV_GPU_VBIOS_GH100_..._96.00.74.00.11
//   device OCSP : OCSP responses for each issuer in testCertChainB64, from
//                 http://ocsp.ndis.nvidia.com, base64 DER, leaf-to-root order
//   RIM OCSP    : same, for the certificate chain embedded in each RIM's XML signature
//
// Both RIMs are base64 of the raw XML document. Capture them at a known instant
// and set testTime to that instant, otherwise the OCSP recency check will fail.
// ---------------------------------------------------------------------------

// testDriverRimB64 is the base64 RIM for driver version testDriverVersion. EMPTY: not captured.
const testDriverRimB64 = ""

// testVbiosRimB64 is the base64 RIM for VBIOS version testVbiosVersion. EMPTY: not captured.
const testVbiosRimB64 = ""

// testDeviceOcspB64 holds the OCSP responses for testCertChainB64, leaf issuer
// first. EMPTY: not captured.
var testDeviceOcspB64 = []string{}

// testRimOcspB64 holds the OCSP responses for the RIM signing chains, keyed as
// fetch_nvidia_collateral stores them. EMPTY: not captured.
var testRimOcspB64 = map[string][]string{}

// hasFullCollateral reports whether the fixtures above have been filled in.
func hasFullCollateral() bool {
	return testDriverRimB64 != "" && testVbiosRimB64 != "" && len(testDeviceOcspB64) > 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testRawReport(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(testReportB64)
	if err != nil {
		t.Fatalf("failed to decode test report: %v", err)
	}
	return raw
}

func testNonce(t *testing.T) []byte {
	t.Helper()
	nonce, err := hex.DecodeString(testNonceHex)
	if err != nil {
		t.Fatalf("failed to decode test nonce: %v", err)
	}
	return nonce
}

// testSpdmResponse parses the MEASUREMENTS response out of the captured report.
func testSpdmResponse(t *testing.T) *SpdmMeasurementResponse {
	t.Helper()
	raw := testRawReport(t)
	resp, err := CreateSpdmMeasurementResponseMessage11(raw[SPDM_REQUEST_kRequestLength:], testSignatureLen)
	if err != nil {
		t.Fatalf("failed to parse SPDM response: %v", err)
	}
	return resp
}

// testEvidence assembles the evidence blob exactly as nvidiadriver.GetEvidence does.
func testEvidence(t *testing.T) ar.Evidence {
	t.Helper()
	data, err := cbor.Marshal(internal.NvidiaGPUEvidence{
		Architecture:            testArchitecture,
		UUID:                    testDeviceUUID,
		SignedAttestationReport: testReportB64,
		Certificates:            testCertChainB64,
	})
	if err != nil {
		t.Fatalf("failed to encode test evidence: %v", err)
	}
	return ar.Evidence{Type: ar.TYPE_EVIDENCE_NVIDIA, Data: data}
}

// testCollateral assembles the collateral exactly as nvidiadriver.GetCollateral does.
func testCollateral() ar.Collateral {
	return ar.Collateral{
		Type: ar.TYPE_EVIDENCE_NVIDIA,
		Artifacts: []ar.Artifact{{
			Type: ar.TYPE_NVIDIA_COLLATERAL,
			Events: []ar.Component{{
				Type: ar.TYPE_NVIDIA_COLLATERAL,
				Name: "nvidia collateral",
				NvidiaCollateral: &ar.NvidiaCollateral{
					DriverRIMs:               map[string]string{testDriverVersion: testDriverRimB64},
					VbiosRIMs:                map[string]string{testVbiosVersion: testVbiosRimB64},
					OcspResponsesDeviceCerts: map[string][]string{"device_" + testDeviceUUID: testDeviceOcspB64},
					OcspResponsesRIMCerts:    testRimOcspB64,
				},
			}},
		}},
	}
}

// withFixedTime pins the package clock for the duration of the test.
func withFixedTime(t *testing.T) {
	t.Helper()
	old := now
	now = func() time.Time { return testTime }
	t.Cleanup(func() { now = old })
}

// resetCaches drops all verifier-internal caches so that tests do not observe
// each other's results. The caches are keyed on inputs and bounded by a TTL, so
// in production they are transparent, but in a test they would hide exactly the
// failures the negative cases are asserting on.
func resetCaches(t *testing.T) {
	t.Helper()
	ClearRIMCache()
	chainCacheMu.Lock()
	chainCache = make(map[string]cachedChainEntry)
	chainCacheMu.Unlock()
	ocspCache = sync.Map{}
}

// ---------------------------------------------------------------------------
// SPDM parsing
// ---------------------------------------------------------------------------

func TestParseSpdmMeasurementResponse(t *testing.T) {
	resp := testSpdmResponse(t)

	if got := int(resp.NumberOfBlocks); got != testMeasurementBlocks {
		t.Errorf("NumberOfBlocks = %d, want %d", got, testMeasurementBlocks)
	}
	if got := len(resp.OpaqueFields); got != testOpaqueFields {
		t.Errorf("len(OpaqueFields) = %d, want %d", got, testOpaqueFields)
	}
	if got := len(resp.Signature); got != testSignatureLen {
		t.Errorf("len(Signature) = %d, want %d", got, testSignatureLen)
	}
	if int(resp.MeasurementRecordLength) != len(resp.MeasurementRecordData) {
		t.Errorf("MeasurementRecordLength = %d but MeasurementRecordData is %d bytes",
			resp.MeasurementRecordLength, len(resp.MeasurementRecordData))
	}
}

func TestParseSpdmMeasurementRequest(t *testing.T) {
	raw := testRawReport(t)

	req, err := CreateSpdmMeasurementRequestMessage11(raw[:SPDM_REQUEST_kRequestLength])
	if err != nil {
		t.Fatalf("CreateSpdmMeasurementRequestMessage11() error = %v", err)
	}

	if got, want := hex.EncodeToString(req.nonce[:]), testNonceHex; got != want {
		t.Errorf("request nonce = %s, want %s", got, want)
	}
}

func TestSpdmVersionExtraction(t *testing.T) {
	resp := testSpdmResponse(t)

	driver, err := resp.getDriverVersion()
	if err != nil {
		t.Fatalf("getDriverVersion() error = %v", err)
	}
	if driver != testDriverVersion {
		t.Errorf("driver version = %q, want %q", driver, testDriverVersion)
	}

	vbios, err := resp.getVbiosVersion()
	if err != nil {
		t.Fatalf("getVbiosVersion() error = %v", err)
	}
	if vbios != testVbiosVersion {
		t.Errorf("vbios version = %q, want %q", vbios, testVbiosVersion)
	}
}

// TestSpdmOpaqueNvdec0Status covers the NVDEC0 status field, which VerifyNvidia
// uses to decide whether measurement block 35 is meaningful. 0x55 means the
// engine is disabled and the block must be skipped.
func TestSpdmOpaqueNvdec0Status(t *testing.T) {
	resp := testSpdmResponse(t)

	field := GetSPDMOpaqueFieldOfType(resp, GpuOpaqueDataTypeNvdec0Status)
	if field == nil {
		t.Fatal("NVDEC0 status opaque field not present in report")
	}
	if field[0] != 0x55 {
		t.Errorf("NVDEC0 status = 0x%02X, want 0x55 (disabled) for this fixture", field[0])
	}
}

// TestParseSpdmResponseRejectsMalformed feeds the parser truncated and corrupted
// input. Every case must return an error rather than panic or silently return a
// partially populated response, since this parser runs on attacker-supplied bytes.
func TestParseSpdmResponseRejectsMalformed(t *testing.T) {
	raw := testRawReport(t)
	body := raw[SPDM_REQUEST_kRequestLength:]

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"header only", body[:4]},
		{"truncated before measurement record", body[:8]},
		{"truncated mid measurement record", body[:len(body)/2]},
		{"truncated before signature", body[:len(body)-testSignatureLen-1]},
		{"one byte short", body[:len(body)-1]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := CreateSpdmMeasurementResponseMessage11(tt.data, testSignatureLen)
			if err == nil {
				t.Fatalf("expected error for malformed input, got response %+v", resp)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Measurement record
// ---------------------------------------------------------------------------

func TestParseMeasurementRecord(t *testing.T) {
	resp := testSpdmResponse(t)

	blocks, err := ParseMeasurementRecord(resp.MeasurementRecordData)
	if err != nil {
		t.Fatalf("ParseMeasurementRecord() error = %v", err)
	}
	if len(blocks) != testMeasurementBlocks {
		t.Fatalf("parsed %d measurement blocks, want %d", len(blocks), testMeasurementBlocks)
	}

	// The record is a bare TLV sequence, so the parser derives the block count
	// from the buffer length alone and never consults NumberOfBlocks. Both fields
	// sit inside the signed region, so they cannot disagree in a report that
	// passed the signature check, but assert the invariant here so that a parser
	// change which silently drops a trailing block shows up.
	if len(blocks) != int(resp.NumberOfBlocks) {
		t.Errorf("parsed %d blocks but response header announces NumberOfBlocks=%d",
			len(blocks), resp.NumberOfBlocks)
	}

	// Block 1 is the first non-zero measurement in this fixture. Pinning it
	// catches offset regressions in the record parser that a length check misses.
	const wantBlock1 = "b558fdac9af53b91ff3bdb06ff589859d6fbc1050d875c88329347f24ff7b3d1" +
		"1ac53688ba56db03cf8751913107e0db"
	if got := hex.EncodeToString(blocks[1].Value); got != wantBlock1 {
		t.Errorf("block[1] = %s, want %s", got, wantBlock1)
	}
}

func TestParseMeasurementRecordRejectsTruncated(t *testing.T) {
	resp := testSpdmResponse(t)
	record := resp.MeasurementRecordData

	// Truncations that cut into a block must be rejected rather than yielding a
	// short record. A cut on a block boundary is not an error: the parser walks
	// TLVs until the buffer ends and simply returns fewer blocks, see
	// TestParseMeasurementRecordStopsOnBlockBoundary.
	for _, n := range []int{1, 4, 5, 30, len(record) - 1} {
		if _, err := ParseMeasurementRecord(record[:n]); err == nil {
			t.Errorf("ParseMeasurementRecord(record[:%d]) succeeded, want error", n)
		}
	}
}

func TestParseMeasurementRecordStopsOnBlockBoundary(t *testing.T) {
	resp := testSpdmResponse(t)
	record := resp.MeasurementRecordData

	blockSize := len(record) / testMeasurementBlocks
	if blockSize*testMeasurementBlocks != len(record) {
		t.Skipf("fixture record of %d bytes does not split evenly into %d blocks",
			len(record), testMeasurementBlocks)
	}

	blocks, err := ParseMeasurementRecord(record[:blockSize*2])
	if err != nil {
		t.Fatalf("ParseMeasurementRecord() error = %v", err)
	}
	if len(blocks) != 2 {
		t.Errorf("parsed %d blocks from a two-block prefix, want 2", len(blocks))
	}
}

// ---------------------------------------------------------------------------
// Report signature
// ---------------------------------------------------------------------------

// TestVerifyReportSignature verifies the real ECDSA-P384 signature over the
// captured report using the public key from the leaf of the captured chain.
func TestVerifyReportSignature(t *testing.T) {
	raw := testRawReport(t)

	chainBytes, err := base64.StdEncoding.DecodeString(testCertChainB64)
	if err != nil {
		t.Fatalf("failed to decode cert chain: %v", err)
	}
	chain, err := internal.ParseCertChain(chainBytes)
	if err != nil {
		t.Fatalf("ParseCertChain() error = %v", err)
	}
	if len(chain) != 5 {
		t.Fatalf("parsed %d certificates, want 5", len(chain))
	}

	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key is %T, want *ecdsa.PublicKey", chain[0].PublicKey)
	}

	signed := raw[:len(raw)-testSignatureLen]
	signature := raw[len(raw)-testSignatureLen:]

	if err := VerifyCertChainSignature(pub, signature, signed); err != nil {
		t.Errorf("VerifyCertChainSignature() error = %v, want nil", err)
	}

	t.Run("rejects tampered payload", func(t *testing.T) {
		tampered := make([]byte, len(signed))
		copy(tampered, signed)
		tampered[len(tampered)/2] ^= 0x01
		if err := VerifyCertChainSignature(pub, signature, tampered); err == nil {
			t.Error("VerifyCertChainSignature() accepted a tampered payload")
		}
	})

	t.Run("rejects tampered signature", func(t *testing.T) {
		tampered := make([]byte, len(signature))
		copy(tampered, signature)
		tampered[0] ^= 0x01
		if err := VerifyCertChainSignature(pub, tampered, signed); err == nil {
			t.Error("VerifyCertChainSignature() accepted a tampered signature")
		}
	})

	t.Run("rejects odd length signature", func(t *testing.T) {
		if err := VerifyCertChainSignature(pub, signature[:testSignatureLen-1], signed); err == nil {
			t.Error("VerifyCertChainSignature() accepted an odd-length signature")
		}
	})
}

// ---------------------------------------------------------------------------
// Device certificate chain
// ---------------------------------------------------------------------------

func TestVerifyDeviceCertificateChain(t *testing.T) {
	withFixedTime(t)
	resetCaches(t)

	chainBytes, err := base64.StdEncoding.DecodeString(testCertChainB64)
	if err != nil {
		t.Fatalf("failed to decode cert chain: %v", err)
	}

	deviceFingerprints := []string{testDeviceCaFingerprint}

	if err := verifyCertificateChain(string(chainBytes), deviceFingerprints); err != nil {
		t.Errorf("verifyCertificateChain() error = %v, want nil", err)
	}

	t.Run("rejects wrong root", func(t *testing.T) {
		// The RIM signing root is a real NVIDIA root, but not the one the device
		// chain ends in, so the chain must not be accepted under it.
		if err := verifyCertificateChain(string(chainBytes), []string{testRimCaFingerprint}); err == nil {
			t.Error("verifyCertificateChain() accepted a chain under the wrong root")
		}
	})

	t.Run("rejects unpinned root", func(t *testing.T) {
		// The chain carries its own self-signed root. Without a pinned fingerprint
		// it would anchor in itself, so an empty allowlist must reject it.
		resetCaches(t)
		if err := verifyCertificateChain(string(chainBytes), nil); err == nil {
			t.Error("verifyCertificateChain() accepted a chain without a pinned root")
		}
	})

	t.Run("rejects malformed fingerprint", func(t *testing.T) {
		resetCaches(t)
		if err := verifyCertificateChain(string(chainBytes), []string{"not hex"}); err == nil {
			t.Error("verifyCertificateChain() accepted a malformed reference fingerprint")
		}
	})

	t.Run("rejects empty chain", func(t *testing.T) {
		if err := verifyCertificateChain("", deviceFingerprints); err == nil {
			t.Error("verifyCertificateChain() accepted an empty chain")
		}
	})
}

// ---------------------------------------------------------------------------
// Version policy
// ---------------------------------------------------------------------------

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name    string
		v1, v2  string
		want    int
		wantErr bool
	}{
		{name: "equal", v1: "595.71.05", v2: "595.71.05", want: 0},
		{name: "greater patch", v1: "595.71.06", v2: "595.71.05", want: 1},
		{name: "lower patch", v1: "595.71.04", v2: "595.71.05", want: -1},
		{name: "greater major", v1: "600.0.0", v2: "595.71.05", want: 1},
		// Numeric, not lexicographic: "530.9" must sort below "530.10".
		{name: "numeric not lexicographic", v1: "530.9", v2: "530.10", want: -1},
		{name: "shorter is equal when padded", v1: "595.71", v2: "595.71.0", want: 0},
		{name: "shorter is lower", v1: "595.71", v2: "595.71.5", want: -1},
		{name: "vbios equal", v1: testVbiosVersion, v2: testVbiosVersion, want: 0},
		{name: "non numeric lhs", v1: "abc", v2: "1.0", wantErr: true},
		{name: "non numeric rhs", v1: "1.0", v2: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareVersions(tt.v1, tt.v2)
			if (err != nil) != tt.wantErr {
				t.Fatalf("compareVersions(%q, %q) error = %v, wantErr %v", tt.v1, tt.v2, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Evidence decoding
// ---------------------------------------------------------------------------

// TestVerifyNvidiaRejectsBadEvidence covers the paths VerifyNvidia can reject
// before it needs any collateral, so these run without the missing RIM fixtures.
func TestVerifyNvidiaRejectsBadEvidence(t *testing.T) {
	withFixedTime(t)

	evidence := func(t *testing.T, mutate func(*internal.NvidiaGPUEvidence)) ar.Evidence {
		t.Helper()
		ev := internal.NvidiaGPUEvidence{
			Architecture:            testArchitecture,
			UUID:                    testDeviceUUID,
			SignedAttestationReport: testReportB64,
			Certificates:            testCertChainB64,
		}
		mutate(&ev)
		data, err := cbor.Marshal(ev)
		if err != nil {
			t.Fatalf("failed to encode evidence: %v", err)
		}
		return ar.Evidence{Type: ar.TYPE_EVIDENCE_NVIDIA, Data: data}
	}

	tests := []struct {
		name     string
		evidence ar.Evidence
		policy   *ar.NvidiaPolicy
		code     ar.ErrorCode
	}{
		{
			name:     "not cbor",
			evidence: ar.Evidence{Type: ar.TYPE_EVIDENCE_NVIDIA, Data: []byte("not cbor at all")},
			code:     ar.ParseEvidence,
		},
		{
			name: "unknown architecture",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.Architecture = "TURING"
			}),
			code: ar.MeasurementTypeNotSupported,
		},
		{
			name: "architecture not allowed by policy",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.Architecture = testArchitecture
			}),
			policy: &ar.NvidiaPolicy{AllowedArchitectures: []string{"BLACKWELL"}},
			code:   ar.VerifyPolicies,
		},
		{
			name: "report not base64",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.SignedAttestationReport = "!!! not base64 !!!"
			}),
			code: ar.ParseEvidence,
		},
		{
			name: "report shorter than signature",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.SignedAttestationReport = base64.StdEncoding.EncodeToString(make([]byte, testSignatureLen-1))
			}),
			code: ar.EvidenceLength,
		},
		{
			// A report long enough for the signature but too short to also hold the
			// SPDM request would otherwise be sliced out of bounds.
			name: "report shorter than request plus signature",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.SignedAttestationReport = base64.StdEncoding.EncodeToString(
					make([]byte, testSignatureLen+SPDM_REQUEST_kRequestLength-1))
			}),
			code: ar.EvidenceLength,
		},
		{
			name: "certificates not base64",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.Certificates = "!!! not base64 !!!"
			}),
			code: ar.DecodeCertChain,
		},
		{
			name: "certificates not a chain",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				e.Certificates = base64.StdEncoding.EncodeToString([]byte("no pem here"))
			}),
			code: ar.ParseCert,
		},
		{
			name: "signature does not match report",
			evidence: evidence(t, func(e *internal.NvidiaGPUEvidence) {
				raw := testRawReport(t)
				tampered := make([]byte, len(raw))
				copy(tampered, raw)
				tampered[len(tampered)-1] ^= 0x01
				e.SignedAttestationReport = base64.StdEncoding.EncodeToString(tampered)
			}),
			code: ar.VerifySignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCaches(t)
			result := VerifyNvidia(tt.evidence, testCollateral(), testNonce(t), testManifests(tt.policy))
			ok := result.Summary.Status == ar.StatusSuccess
			if ok {
				t.Error("VerifyNvidia() accepted invalid evidence")
			}
			if result == nil {
				t.Fatal("VerifyNvidia() returned a nil result")
			}
			if result.NvidiaResult == nil {
				t.Fatal("VerifyNvidia() returned a result without NvidiaResult")
			}
			if result.NvidiaResult.MeasurementRIMCheck.Status == ar.StatusSuccess {
				t.Error("MeasurementRIMCheck passed on a rejected report")
			}
			if result.Summary.Status != ar.StatusFail {
				t.Errorf("Summary.Status = %q, want %q", result.Summary.Status, ar.StatusFail)
			}
			if !hasErrorCode(result.Summary, tt.code) {
				t.Errorf("Summary.ErrorCodes = %v, want to contain %v",
					result.Summary.ErrorCodes, tt.code)
			}
			if result.Summary.Details == "" {
				t.Error("Summary.Details is empty, the cause is not reported to the verifier")
			}
		})
	}
}

// testManifests wraps a policy the way the verifier delivers it to VerifyNvidia: in a manifest that
// is not the first one, so that ordering-dependent lookups fail. A policy that pins no root CA is
// rejected, so the fixture fingerprints are filled in for callers that do not care about them.
func testManifests(policy *ar.NvidiaPolicy) []ar.Metadata {
	p := ar.NvidiaPolicy{}
	if policy != nil {
		p = *policy
	}
	if len(p.DeviceCaFingerprints) == 0 {
		p.DeviceCaFingerprints = []string{testDeviceCaFingerprint}
	}
	if len(p.RimCaFingerprints) == 0 {
		p.RimCaFingerprints = []string{testRimCaFingerprint}
	}

	rtm := ar.Metadata{}
	rtm.Name = "rtm"
	gpu := ar.Metadata{}
	gpu.Name = "gpu"
	gpu.NvidiaPolicy = &p
	return []ar.Metadata{rtm, gpu}
}

// hasErrorCode reports whether the result carries the given error code.
func hasErrorCode(r ar.Result, code ar.ErrorCode) bool {
	for _, c := range r.ErrorCodes {
		if c == code {
			return true
		}
	}
	return false
}

// TestVerifyNvidiaEnforceNonce checks that a mismatched nonce is fatal when the
// policy demands it and tolerated otherwise. It stops at the RIM lookup, which
// is the first step that needs the missing collateral, so it only asserts on the
// signature check having passed.
func TestVerifyNvidiaEnforceNonce(t *testing.T) {
	withFixedTime(t)

	wrongNonce := make([]byte, len(testNonce(t)))

	t.Run("mismatch rejected when enforced", func(t *testing.T) {
		resetCaches(t)
		result := VerifyNvidia(testEvidence(t), testCollateral(), wrongNonce,
			testManifests(&ar.NvidiaPolicy{EnforceNonce: true}))
		ok := result.Summary.Status == ar.StatusSuccess
		if ok {
			t.Error("VerifyNvidia() accepted a report with a mismatched nonce under EnforceNonce")
		}
		if result.NvidiaResult.MeasurementSignatureCheck.Status != ar.StatusSuccess {
			t.Error("signature check should have passed before the nonce was compared")
		}
		if result.NvidiaResult.MeasurementRIMCheck.Status == ar.StatusSuccess {
			t.Error("MeasurementRIMCheck passed despite the nonce mismatch")
		}
		if result.Summary.Status != ar.StatusFail {
			t.Errorf("Summary.Status = %q, want %q", result.Summary.Status, ar.StatusFail)
		}
		if !hasErrorCode(result.Summary, ar.Freshness) {
			t.Errorf("Summary.ErrorCodes = %v, want to contain %v",
				result.Summary.ErrorCodes, ar.Freshness)
		}
		if result.Freshness.Status != ar.StatusFail {
			t.Errorf("Freshness.Status = %q, want %q", result.Freshness.Status, ar.StatusFail)
		}
	})

	t.Run("mismatch tolerated when not enforced", func(t *testing.T) {
		resetCaches(t)
		result := VerifyNvidia(testEvidence(t), testCollateral(), wrongNonce, testManifests(nil))
		if result.NvidiaResult.MeasurementSignatureCheck.Status != ar.StatusSuccess {
			t.Error("signature check should have passed")
		}
		if result.Freshness.Status != ar.StatusFail {
			t.Errorf("Freshness.Status = %q, want %q", result.Freshness.Status, ar.StatusFail)
		}
	})
}

// ---------------------------------------------------------------------------
// Full verification
// ---------------------------------------------------------------------------

// TestVerifyNvidia is the end-to-end test. It needs the driver RIM, the VBIOS RIM
// and the OCSP responses listed under "Missing fixtures" above; until those are
// captured it skips rather than asserting on an incomplete fixture.
func TestVerifyNvidia(t *testing.T) {
	if !hasFullCollateral() {
		t.Skip("missing NVIDIA collateral fixtures (driver RIM, VBIOS RIM, device OCSP responses) " +
			"- see the 'Missing fixtures' block in nvidia_test.go")
	}

	withFixedTime(t)

	tests := []struct {
		name   string
		policy *ar.NvidiaPolicy
		want   bool
	}{
		{
			name:   "no policy",
			policy: nil,
			want:   true,
		},
		{
			name: "minimum versions satisfied",
			policy: &ar.NvidiaPolicy{
				DriverMinVersion: testDriverVersion,
				VbiosMinVersion:  testVbiosVersion,
			},
			want: true,
		},
		{
			name: "driver below minimum",
			policy: &ar.NvidiaPolicy{
				DriverMinVersion: "999.0.0",
				VbiosMinVersion:  testVbiosVersion,
			},
			want: false,
		},
		{
			name: "vbios below minimum",
			policy: &ar.NvidiaPolicy{
				DriverMinVersion: testDriverVersion,
				VbiosMinVersion:  "999.00.00.00.00",
			},
			want: false,
		},
		{
			name: "nonce enforced and matching",
			policy: &ar.NvidiaPolicy{
				EnforceNonce: true,
			},
			want: true,
		},
		{
			name: "ocsp required for rims",
			policy: &ar.NvidiaPolicy{
				RequireOCSPForRIMs: true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCaches(t)
			result := VerifyNvidia(testEvidence(t), testCollateral(), testNonce(t), testManifests(tt.policy))
			ok := result.Summary.Status == ar.StatusSuccess
			if ok != tt.want {
				t.Errorf("VerifyNvidia() ok = %v, want %v", ok, tt.want)
			}
			if !tt.want {
				return
			}
			r := result.NvidiaResult
			for name, check := range map[string]ar.Result{
				"MeasurementSignatureCheck": r.MeasurementSignatureCheck,
				"MeasurementRIMCheck":       r.MeasurementRIMCheck,
				"RIMSignatureCheck":         r.RIMSignatureCheck,
				"DeviceRecencyCheck":        r.DeviceRecencyCheck,
				"PolicyCheck":               r.PolicyCheck,
			} {
				if check.Status != ar.StatusSuccess {
					t.Errorf("%v.Status = %q, want %q: %v",
						name, check.Status, ar.StatusSuccess, check.Details)
				}
			}

			// Without the policy demanding OCSP nothing was checked, which is a
			// warning on the recency check rather than a pass
			wantRecency := ar.StatusWarn
			if tt.policy != nil && tt.policy.RequireOCSPForRIMs {
				wantRecency = ar.StatusSuccess
			}
			if r.RIMRecencyCheck.Status != wantRecency {
				t.Errorf("RIMRecencyCheck.Status = %q, want %q",
					r.RIMRecencyCheck.Status, wantRecency)
			}
		})
	}
}

// TestGetRIMUnionForVersions covers RIM lookup and merging. Needs the RIM fixtures.
func TestGetRIMUnionForVersions(t *testing.T) {
	if !hasFullCollateral() {
		t.Skip("missing NVIDIA RIM fixtures - see the 'Missing fixtures' block in nvidia_test.go")
	}

	withFixedTime(t)

	t.Run("known versions", func(t *testing.T) {
		resetCaches(t)
		rim, err := GetRIMUnionForVersions(testCollateral(), testDriverVersion, testVbiosVersion, false,
			[]string{testRimCaFingerprint})
		if err != nil {
			t.Fatalf("GetRIMUnionForVersions() error = %v", err)
		}
		active := 0
		for i := range rim.Pairs {
			if rim.Pairs[i].Active {
				active++
			}
		}
		if active == 0 {
			t.Error("RIM union has no active measurement pairs")
		}
	})

	t.Run("unknown driver version", func(t *testing.T) {
		resetCaches(t)
		if _, err := GetRIMUnionForVersions(testCollateral(), "1.2.3", testVbiosVersion, false,
			[]string{testRimCaFingerprint}); err == nil {
			t.Error("GetRIMUnionForVersions() accepted an unknown driver version")
		}
	})

	t.Run("unknown vbios version", func(t *testing.T) {
		resetCaches(t)
		if _, err := GetRIMUnionForVersions(testCollateral(), testDriverVersion, "1.2.3", false,
			[]string{testRimCaFingerprint}); err == nil {
			t.Error("GetRIMUnionForVersions() accepted an unknown vbios version")
		}
	})
}

// ---------------------------------------------------------------------------
// Hardening regressions
// ---------------------------------------------------------------------------

// attackerEvidence builds evidence around an arbitrary report body, signed with a
// freshly generated key whose self-signed certificate is presented as the device
// chain. It models what any peer can send: the report signature is self-consistent,
// so verification proceeds past the signature check, but the chain does not anchor
// in the NVIDIA device root and the report is rejected further down.
func attackerEvidence(t *testing.T, body []byte) ar.Evidence {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attacker leaf"},
		NotBefore:    testTime.Add(-time.Hour),
		NotAfter:     testTime.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	digest := sha512.Sum384(body)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign report: %v", err)
	}
	sig := make([]byte, testSignatureLen)
	r.FillBytes(sig[:testSignatureLen/2])
	s.FillBytes(sig[testSignatureLen/2:])

	data, err := cbor.Marshal(internal.NvidiaGPUEvidence{
		Architecture:            testArchitecture,
		UUID:                    "GPU-attacker",
		SignedAttestationReport: base64.StdEncoding.EncodeToString(append(append([]byte{}, body...), sig...)),
		Certificates: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	})
	if err != nil {
		t.Fatalf("failed to encode evidence: %v", err)
	}
	return ar.Evidence{Type: ar.TYPE_EVIDENCE_NVIDIA, Data: data}
}

// TestParseSpdmMeasurementRequestRejectsMalformed covers the request prefix of the
// report. VerifyNvidia now anchors the device chain before it parses anything out
// of the report, so these cases are exercised directly rather than through it.
func TestParseSpdmMeasurementRequestRejectsMalformed(t *testing.T) {
	raw := testRawReport(t)

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name:   "bad spdm version",
			mutate: func(b []byte) { b[0] = 0x00 },
		},
		{
			name:   "bad request response code",
			mutate: func(b []byte) { b[1] = 0x00 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := append([]byte{}, raw[:SPDM_REQUEST_kRequestLength]...)
			tt.mutate(prefix)
			if _, err := CreateSpdmMeasurementRequestMessage11(prefix); err == nil {
				t.Error("CreateSpdmMeasurementRequestMessage11() accepted a malformed request")
			}
		})
	}
}

// TestVerifyNvidiaAnchorsChainBeforeSignature is a regression test for a
// reporting-integrity defect: the report signature used to be checked against the
// leaf of the caller-supplied chain, and MeasurementSignatureCheck was set from
// that result, ~70 lines before the chain was anchored in the NVIDIA device root.
// A wholly attacker-generated report therefore came back with
// MeasurementSignatureCheck=true, which is what policy engines consume.
func TestVerifyNvidiaAnchorsChainBeforeSignature(t *testing.T) {
	withFixedTime(t)
	resetCaches(t)

	raw := testRawReport(t)
	body := append([]byte{}, raw[:len(raw)-testSignatureLen]...)

	result := VerifyNvidia(attackerEvidence(t, body), testCollateral(), testNonce(t), testManifests(nil))
	ok := result.Summary.Status == ar.StatusSuccess
	if ok {
		t.Fatal("VerifyNvidia() accepted a self-signed report")
	}
	sigCheck := result.NvidiaResult.MeasurementSignatureCheck
	if sigCheck.Status != ar.StatusFail {
		t.Errorf("MeasurementSignatureCheck.Status = %q, want %q for a report signed with an untrusted key",
			sigCheck.Status, ar.StatusFail)
	}
	// The check which detected the failure carries the reason, the summary mirrors it
	if !hasErrorCode(sigCheck, ar.VerifyCertChain) {
		t.Errorf("MeasurementSignatureCheck.ErrorCodes = %v, want to contain %v",
			sigCheck.ErrorCodes, ar.VerifyCertChain)
	}
	if sigCheck.Details == "" {
		t.Error("MeasurementSignatureCheck.Details is empty, the cause is not reported")
	}
	if !hasErrorCode(result.Summary, ar.VerifyCertChain) {
		t.Errorf("Summary.ErrorCodes = %v, want to contain %v",
			result.Summary.ErrorCodes, ar.VerifyCertChain)
	}
}

// TestCompareLooseVersions covers the inforom and GSP minimum-version checks, which
// compared version strings with < and therefore ranked "1.10" below "1.9".
func TestCompareLooseVersions(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{"equal", "1.1", "1.1", 0},
		{"numeric not lexicographic", "1.10", "1.9", 1},
		{"numeric not lexicographic reversed", "1.9", "1.10", -1},
		{"greater major", "2.0", "1.99", 1},
		{"shorter is lower", "1", "1.1", -1},
		{"leading zeros are numeric", "6.016", "6.16", 0},
		{"non numeric image version equal", "G520.0200.00.04", "G520.0200.00.04", 0},
		{"non numeric image version numeric tail", "G520.0200.00.10", "G520.0200.00.4", 1},
		{"non numeric prefix falls back to string", "G520.0200.00.04", "G521.0100.00.01", -1},
		{"empty is lowest", "", "1.1", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareLooseVersions(tt.v1, tt.v2); got != tt.want {
				t.Errorf("compareLooseVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

// TestEnforceExtraPolicyMinVersions pins the behaviour the loose comparison exists
// for: a device newer than the minimum must pass even when the string comparison
// would have rejected it.
func TestEnforceExtraPolicyMinVersions(t *testing.T) {
	ev := internal.NvidiaDeviceUnsignedEvidence{
		UUID:                testDeviceUUID,
		InforomEccVersion:   "6.16",
		InforomImageVersion: "G520.0200.00.10",
		GspFirmwareVersion:  "595.71.05",
	}

	t.Run("accepts a newer version that sorts lower as a string", func(t *testing.T) {
		policy := &ar.NvidiaExtraSecurityPolicy{
			InforomEccMinVersion:   "6.9",
			InforomImageMinVersion: "G520.0200.00.4",
			GspFirmwareMinVersion:  "595.9.05",
		}
		if err := enforceExtraPolicy(&ev, policy); err != nil {
			t.Errorf("enforceExtraPolicy() rejected a compliant device: %v", err)
		}
	})

	t.Run("rejects a version below the minimum", func(t *testing.T) {
		policy := &ar.NvidiaExtraSecurityPolicy{InforomEccMinVersion: "6.17"}
		if err := enforceExtraPolicy(&ev, policy); err == nil {
			t.Error("enforceExtraPolicy() accepted a device below the minimum version")
		}
	})

	t.Run("unset minimum does not constrain", func(t *testing.T) {
		if err := enforceExtraPolicy(&ev, &ar.NvidiaExtraSecurityPolicy{}); err != nil {
			t.Errorf("enforceExtraPolicy() rejected on an empty policy: %v", err)
		}
	})
}

// TestNvidiaPolicyFromManifests covers the policy lookup. Which manifest carries the
// policy must not depend on manifest ordering, and two competing policies must be
// rejected rather than silently resolved.
func TestNvidiaPolicyFromManifests(t *testing.T) {
	policy := &ar.NvidiaPolicy{EnforceNonce: true}
	withPolicy := func(name string, p *ar.NvidiaPolicy) ar.Metadata {
		m := ar.Metadata{}
		m.Name = name
		m.NvidiaPolicy = p
		return m
	}

	t.Run("no manifests", func(t *testing.T) {
		got, err := nvidiaPolicyFromManifests(nil)
		if err != nil {
			t.Fatalf("nvidiaPolicyFromManifests() error = %v", err)
		}
		if got != nil {
			t.Errorf("policy = %v, want nil", got)
		}
	})

	t.Run("policy in a later manifest", func(t *testing.T) {
		got, err := nvidiaPolicyFromManifests([]ar.Metadata{
			withPolicy("rtm", nil),
			withPolicy("os", nil),
			withPolicy("gpu", policy),
		})
		if err != nil {
			t.Fatalf("nvidiaPolicyFromManifests() error = %v", err)
		}
		if got != policy {
			t.Errorf("policy = %v, want the policy from the third manifest", got)
		}
	})

	t.Run("conflicting policies are rejected", func(t *testing.T) {
		_, err := nvidiaPolicyFromManifests([]ar.Metadata{
			withPolicy("gpu-a", policy),
			withPolicy("gpu-b", &ar.NvidiaPolicy{}),
		})
		if err == nil {
			t.Error("nvidiaPolicyFromManifests() accepted two competing policies")
		}
	})

	// The device chain and the RIM signing chain both carry their own self-signed root.
	// A missing policy, or a policy which pins no fingerprint, leaves the verifier with
	// nothing to anchor them in and must reject the report rather than trust the wire
	t.Run("unanchored policies are rejected", func(t *testing.T) {
		withFixedTime(t)

		tests := []struct {
			name   string
			policy *ar.NvidiaPolicy
		}{
			{name: "no policy at all", policy: nil},
			{name: "no fingerprints", policy: &ar.NvidiaPolicy{}},
			{
				name:   "no device fingerprints",
				policy: &ar.NvidiaPolicy{RimCaFingerprints: []string{testRimCaFingerprint}},
			},
			{
				name:   "no rim fingerprints",
				policy: &ar.NvidiaPolicy{DeviceCaFingerprints: []string{testDeviceCaFingerprint}},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resetCaches(t)
				result := VerifyNvidia(testEvidence(t), testCollateral(), testNonce(t),
					[]ar.Metadata{withPolicy("gpu", tt.policy)})
				ok := result.Summary.Status == ar.StatusSuccess
				if ok {
					t.Error("VerifyNvidia() accepted evidence without pinned root CAs")
				}
				if !hasErrorCode(result.NvidiaResult.PolicyCheck, ar.PolicyNotPresent) {
					t.Errorf("PolicyCheck.ErrorCodes = %v, want to contain %v",
						result.NvidiaResult.PolicyCheck.ErrorCodes, ar.PolicyNotPresent)
				}
				if !hasErrorCode(result.Summary, ar.PolicyNotPresent) {
					t.Errorf("Summary.ErrorCodes = %v, want to contain %v",
						result.Summary.ErrorCodes, ar.PolicyNotPresent)
				}
				if result.NvidiaResult.MeasurementSignatureCheck.Status != "" {
					t.Error("MeasurementSignatureCheck ran, verification should stop before the signature")
				}
			})
		}
	})

	t.Run("conflict fails the measurement", func(t *testing.T) {
		withFixedTime(t)
		resetCaches(t)

		result := VerifyNvidia(testEvidence(t), testCollateral(), testNonce(t),
			[]ar.Metadata{withPolicy("gpu-a", policy), withPolicy("gpu-b", &ar.NvidiaPolicy{})})
		ok := result.Summary.Status == ar.StatusSuccess
		if ok {
			t.Error("VerifyNvidia() accepted evidence under two competing policies")
		}
		if !hasErrorCode(result.Summary, ar.VerifyPolicies) {
			t.Errorf("Summary.ErrorCodes = %v, want to contain %v",
				result.Summary.ErrorCodes, ar.VerifyPolicies)
		}
	})
}

// TestOcspResponseIsBoundToCertificate checks that a response is only accepted for
// the certificate it was actually issued for. The responses come from the attesting
// party, so without this binding a peer holding a revoked certificate could present
// a good response for any sibling certificate under the same issuer.
func TestOcspResponseIsBoundToCertificate(t *testing.T) {
	withFixedTime(t)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             testTime.Add(-time.Hour),
		NotAfter:              testTime.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	leaf := func(serial int64, cn string) *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    testTime.Add(-time.Hour),
			NotAfter:     testTime.Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("failed to create leaf certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("failed to parse leaf certificate: %v", err)
		}
		return cert
	}

	attested := leaf(100, "attested device")
	sibling := leaf(200, "sibling device")

	goodResponseFor := func(cert *x509.Certificate) string {
		der, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.SerialNumber,
			ThisUpdate:   testTime.Add(-time.Hour),
			NextUpdate:   testTime.Add(time.Hour),
		}, caKey)
		if err != nil {
			t.Fatalf("failed to create OCSP response: %v", err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}

	chain := []*x509.Certificate{attested, ca}

	t.Run("accepts matching response", func(t *testing.T) {
		resetCaches(t)
		if err := VerifyCertificateChainWithOCSP([]string{goodResponseFor(attested)}, chain, false); err != nil {
			t.Errorf("VerifyCertificateChainWithOCSP() error = %v, want nil", err)
		}
	})

	t.Run("rejects response for a sibling certificate", func(t *testing.T) {
		resetCaches(t)
		if err := VerifyCertificateChainWithOCSP([]string{goodResponseFor(sibling)}, chain, false); err == nil {
			t.Error("VerifyCertificateChainWithOCSP() accepted a response issued for a different certificate")
		}
	})
}
