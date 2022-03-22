// Copyright (c) 2021 Fraunhofer AISEC
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

package main

// Install github packages with "go get [url]"
import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"path"
	"path/filepath"
	"sort"

	"encoding/json"

	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"

	// local modules
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
)

// Converts Protobuf hashtype to crypto.SignerOpts
func convertHash(hashtype ci.HashFunction, pssOpts *ci.PSSOptions) (crypto.SignerOpts, error) {
	var hash crypto.Hash
	var len int
	switch hashtype {
	case ci.HashFunction_SHA256:
		hash = crypto.SHA256
		len = 32
	case ci.HashFunction_SHA384:
		hash = crypto.SHA384
		len = 48
	case ci.HashFunction_SHA512:
		len = 64
		hash = crypto.SHA512
	default:
		return crypto.SHA512, fmt.Errorf("[cmcd] Hash function not implemented: %v", hashtype)
	}
	if pssOpts != nil {
		saltlen := int(pssOpts.SaltLength)
		// go-attestation / go-tpm does not allow -1 as definition for length of hash
		if saltlen < 0 {
			log.Warning("Signature Options: Adapted RSA PSS Salt length to length of hash: ", len)
			saltlen = len
		}
		return &rsa.PSSOptions{SaltLength: saltlen, Hash: hash}, nil
	}
	return hash, nil
}

// Returns either the unmodified absolute path or the absolute path
// retrieved from a path relative to a base path
func getFilePath(p, base string) string {
	if path.IsAbs(p) {
		return p
	}
	ret, _ := filepath.Abs(filepath.Join(base, p))
	return ret
}

func getPcrs(rtmManifest, osManifest []byte) []int {

	// Unpack the signed RTM Manifest
	var rtmMan ar.RtmManifest
	jws, err := jose.ParseSigned(string(rtmManifest))
	if err != nil {
		log.Warn("Failed to parse RTM Manifest - ", err)
	} else {
		data := jws.UnsafePayloadWithoutVerification()
		err = json.Unmarshal(data, &rtmMan)
		if err != nil {
			log.Warn("Failed to unmarshal data from RTM Manifest - ", err)
		}
	}

	// Unpack the signed OS Manifest
	var osMan ar.OsManifest
	jws, err = jose.ParseSigned(string(osManifest))
	if err != nil {
		log.Warn("Failed to parse OS Manifest - ", err)
	} else {
		data := jws.UnsafePayloadWithoutVerification()
		err = json.Unmarshal(data, &osMan)
		if err != nil {
			log.Warn("Failed to unmarshal data from OS Manifst - ", err)
		}
	}

	// Generate the list of PCRs to be included in the quote
	pcrs := make([]int, 0)
	log.Debug("Parsing ", len(rtmMan.Verifications), " RTM verifications")
	for _, ver := range rtmMan.Verifications {
		if !exists(ver.Pcr, pcrs) {
			pcrs = append(pcrs, ver.Pcr)
		}
	}
	log.Debug("Parsing ", len(osMan.Verifications), " OS verifications")
	for _, ver := range osMan.Verifications {
		if !exists(ver.Pcr, pcrs) {
			pcrs = append(pcrs, ver.Pcr)
		}
	}

	sort.Ints(pcrs)

	return pcrs
}

func exists(i int, arr []int) bool {
	for _, elem := range arr {
		if elem == i {
			return true
		}
	}
	return false
}

func printConfig(c *config) {
	log.Info("Using the following configuration:")
	log.Info("CMC Port                   : ", c.Port)
	log.Info("\tConfiguration Server URL : ", c.ServerAddr)
	log.Info("\tConfiguration Server Path: ", c.ServerPath)
	log.Info("\tLocal Config Path        : ", c.LocalPath)
	log.Info("\tFetch Metadata           : ", c.FetchMetadata)
	log.Info("\tUse IMA                  : ", c.UseIma)
	log.Info("\tIMA PCR                  : ", c.ImaPcr)
	log.Info("\tInternal Data Path       : ", c.internalPath)
	log.Info("\tAK Encrypted Key Path    : ", c.akPath)
	log.Info("\tAK Certificate Path      : ", c.akCertPath)
	log.Info("\tTLS Key Encrypted Path   : ", c.tlsKeyPath)
	log.Info("\tTLS Key Certificate Path : ", c.tlsCertPath)
	log.Info("\tDevice Sub CA Cert Path  : ", c.deviceSubCaPath)
	log.Info("\tCA Certificate Path      : ", c.caPath)
}
