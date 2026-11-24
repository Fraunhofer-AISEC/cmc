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

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/rvps/api"
	"github.com/Fraunhofer-AISEC/cmc/rvps/store"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	index       store.Index
	blobs       store.BlobStore
	metadataCAs []*x509.Certificate
}

const (
	maxUploadSize = 20_000_000
	serverTimeout = 60 * time.Second
)

func RunServer(ctx context.Context, index store.Index, blobs store.BlobStore, metadataCAs []*x509.Certificate, addr string, tlsKey crypto.PrivateKey, tlsCaChain []*x509.Certificate) error {
	s := &Server{index: index, blobs: blobs, metadataCAs: metadataCAs}

	// the service is only provided via tls, and only verified metadata is accepted
	if tlsKey == nil || len(tlsCaChain) == 0 {
		return errors.New("tls key and certificate chain are required")
	}
	if len(metadataCAs) == 0 {
		return errors.New("trusted metadata certificates are required")
	}

	// configure the tls parameter
	var tlsUnpackedChain [][]byte
	for _, c := range tlsCaChain {
		tlsUnpackedChain = append(tlsUnpackedChain, c.Raw)
	}
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.NoClientCert,
		ClientCAs:        nil,
		Certificates: []tls.Certificate{
			{
				Certificate: tlsUnpackedChain,
				PrivateKey:  tlsKey,
				Leaf:        tlsCaChain[0],
			},
		},
	}

	// try to create the http server and start it
	httpServer := http.Server{
		Addr:         addr,
		Handler:      http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) { s.handleDispatch(req, resp) }),
		TLSConfig:    tlsCfg,
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
		IdleTimeout:  serverTimeout,
	}

	log.Infof("Starting HTTPS server on (%v)", httpServer.Addr)
	errs := make(chan error, 1)
	go func() { errs <- httpServer.ListenAndServeTLS("", "") }()

	// wait for the server to fail or the context to be cancelled
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		log.Info("Shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("failed to shut down server: %w", err)
		}
		return nil
	}
}

func (s *Server) handleDispatch(req *http.Request, resp http.ResponseWriter) {
	// parse paths of the form [/<type or alias>/<name>] used to fetch metadata by name
	name, kind, kindOk := "", "", false
	if splitPath := strings.Split(req.URL.Path, "/")[1:]; len(splitPath) == 2 {
		kind, kindOk = ResolveMetadataType(splitPath[0])
		name = splitPath[1]
	}

	// dispatch by method and path (hard known paths take precedence over type/alias paths)
	switch {
	case req.Method == "GET" && req.URL.Path == "/list":
		s.handleEnumerate(req, resp)
	case req.Method == "POST" && req.URL.Path == "/metadata":
		s.handleUpload(req, resp)
	case req.Method == "POST" && req.URL.Path == "/query":
		s.handleQuery(req, resp)
	case req.Method == "GET" && strings.HasPrefix(req.URL.Path, "/metadata/"):
		s.handleFetchId(req, resp, strings.TrimPrefix(req.URL.Path, "/metadata/"))
	case req.Method == "GET" && kindOk:
		s.handleFetchName(req, resp, kind, name)
	default:
		resp.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(resp, "Resource [%v] not found", req.URL.Path)
	}
}
func handleInternalError(resp http.ResponseWriter, err string) {
	log.Warnf("Internal error: %v", err)

	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusInternalServerError)
	resp.Write([]byte("Internal error occurred while performing the requested operation"))
}
func handleBadRequest(resp http.ResponseWriter, format string, args ...any) {
	msg := fmt.Sprintf("Bad request: %v", fmt.Sprintf(format, args...))
	log.Warn(msg)

	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusBadRequest)
	resp.Write([]byte(msg))
}
func handleSendEntry(resp http.ResponseWriter, what string, entry *MetadataFull) {
	// check if no entry was found
	if entry == nil {
		log.Debugf("No metadata with %v found", what)
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
		resp.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(resp, "No metadata with %v found", what)
		return
	}

	// setup the content type to match the raw format
	contentType := "application/octet-stream"
	switch entry.Info.Format {
	case "json":
		contentType = "application/json"
	case "cbor":
		contentType = "application/cbor"
	default:
		log.Debugf("Unknown format encountered: %v", entry.Info.Format)
	}

	// send the actual raw metadata
	resp.Header().Set("X-Metadata-Id", entry.Info.Id)
	resp.Header().Set("X-Metadata-Name", entry.Info.Name)
	resp.Header().Set("X-Metadata-Type", entry.Info.Type)
	resp.Header().Set("X-Metadata-Version", entry.Info.Version)
	resp.Header().Set("X-Metadata-Signer", entry.Info.Signer)
	resp.Header().Set("Content-Type", contentType)
	resp.WriteHeader(http.StatusOK)
	resp.Write(entry.Raw)
}
func handleReadUpload(req *http.Request, resp http.ResponseWriter, contentType string) []byte {
	// check if the content type needs to be validated
	if contentType != "" {
		if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), contentType) {
			handleBadRequest(resp, "request payload of type [%v] expected", contentType)
			return nil
		}
	}

	// read the body and ensure its not too large
	body, err := io.ReadAll(http.MaxBytesReader(resp, req.Body, maxUploadSize))
	if err == nil {
		return body
	}
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		handleBadRequest(resp, "failed to read body: %v", err)
		return nil
	}

	// notify the client about the upload constraints
	log.Warnf("Rejecting too large upload of %v bytes", maxUploadSize)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusRequestEntityTooLarge)
	fmt.Fprintf(resp, "Body exceeds the maximum size of %v bytes", maxUploadSize)
	return nil
}
func (s *Server) handleEnumerate(req *http.Request, resp http.ResponseWriter) {
	query := req.URL.Query()
	kind, name, signer := query.Get("type"), query.Get("name"), strings.ToLower(query.Get("signer"))
	log.Tracef("Enumeration for [type: %v] [name: %v] [signer: %v] [offset: %v]", kind, name, signer, query.Get("offset"))

	// parse the optional offset into the listing
	offset := uint64(0)
	if raw := query.Get("offset"); raw != "" {
		var err error
		if offset, err = strconv.ParseUint(raw, 10, 32); err != nil {
			handleBadRequest(resp, "malformed offset (%v)", raw)
			return
		}
	}

	// validate the name and signer formatting and resolve the type
	if name != "" && !RegexNameCheck.MatchString(name) {
		handleBadRequest(resp, "malformed name (%v)", name)
		return
	}
	if signer != "" && !RegexHashCheck.MatchString(signer) {
		handleBadRequest(resp, "malformed signer (%v)", signer)
		return
	}
	if kind != "" {
		if resolved, ok := ResolveMetadataType(kind); !ok {
			handleBadRequest(resp, "unsupported metadata type (%v)", kind)
			return
		} else {
			kind = resolved
		}
	}

	// query the index for the information
	entries, err := s.index.List(req.Context(), store.Filter{Kind: kind, Name: name, Signer: signer}, uint(offset))
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to enumerate metadata: %v", err))
		return
	}
	infos := make([]MetadataInfo, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, LoadMetadataInfo(&entry))
	}

	// send the enumeration information as json encoded back
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	json.NewEncoder(resp).Encode(infos)
}
func (s *Server) handleUpload(req *http.Request, resp http.ResponseWriter) {
	log.Tracef("Uploading metadata")

	// read the request body (unknown content type) and ensure its not empty
	body := handleReadUpload(req, resp, "")
	if body == nil {
		return
	}
	if len(body) == 0 {
		handleBadRequest(resp, "empty body")
		return
	}

	// try to parse the uploaded metadata
	entry, err := ParseMetadata(body, s.metadataCAs)
	if err != nil {
		handleBadRequest(resp, "failed to parse metadata: %v", err)
		return
	}

	// convert the parsed entry to its index representation
	entry.Created = time.Now().UTC().Format(time.RFC3339)
	indexEntry, err := StoreMetadata(entry)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to convert metadata: %v", err))
		return
	}

	// write the blob first, as blob without index is harmless, but an index must point at a valid blob
	if err := s.blobs.Put(req.Context(), entry.Id, body); err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to store metadata blob: %v", err))
		return
	}
	inserted, err := s.index.Insert(req.Context(), *indexEntry)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to insert metadata: %v", err))
		return
	}

	// check if the data could not be inserted as they are already in the index
	if !inserted {
		msg := fmt.Sprintf("Metadata %v %v with id %v already exist", entry.Type, entry.Name, entry.Id)
		log.Debug(msg)

		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
		resp.WriteHeader(http.StatusConflict)
		resp.Write([]byte(msg))
		return
	}

	// return the successful insertion
	log.Infof("Inserted %v %v version %v (id %v) into the index", entry.Type, entry.Name, entry.Version, entry.Id)
	resp.Header().Set("X-Metadata-Id", entry.Id)
	resp.Header().Set("X-Metadata-Name", entry.Name)
	resp.Header().Set("X-Metadata-Type", entry.Type)
	resp.Header().Set("X-Metadata-Version", entry.Version)
	resp.Header().Set("X-Metadata-Signer", entry.Signer)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	fmt.Fprintf(resp, "Metadata %v (id: %v) inserted", entry.Name, entry.Id)
}
func (s *Server) handleQuery(req *http.Request, resp http.ResponseWriter) {
	log.Trace("Querying metadata")

	// read the request body and parse it
	body := handleReadUpload(req, resp, "application/json")
	if body == nil {
		return
	}
	queryRequest := &api.QueryRequest{}
	if err := json.Unmarshal(body, queryRequest); err != nil {
		handleBadRequest(resp, "malformed request body: %v", err)
		return
	}

	// validate the consistency and version of the request and sanitize the inputs
	if queryRequest.Version != api.Version {
		handleBadRequest(resp, "unsupported API version [%v] only %v supported", queryRequest.Version, api.Version)
		return
	}
	for _, id := range queryRequest.Ids {
		if !RegexHashCheck.MatchString(id) {
			handleBadRequest(resp, "malformed id (%v)", id)
			return
		}
	}
	for i, name := range queryRequest.Names {
		if !RegexNameCheck.MatchString(name.Name) {
			handleBadRequest(resp, "malformed name (%v)", name.Name)
			return
		}
		if resolved, ok := ResolveMetadataType(name.Type); !ok {
			handleBadRequest(resp, "unsupported metadata type (%v) for %v", name.Type, name.Name)
			return
		} else {
			queryRequest.Names[i].Type = resolved
		}
	}
	queryResponse, resolver := &api.QueryResponse{
		Version:  api.Version,
		Metadata: make(map[string]api.QueryMetadataEntry),
	}, NewMetadataResolver()

	// load all of the requested ids
	for _, id := range queryRequest.Ids {
		log.Tracef("Fetching metadata by id: %v", id)

		entry, err := s.unpackById(req.Context(), id)
		if err != nil {
			handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by id (%v): %v", id, err))
			return
		}
		if !resolver.AddLoaded("", "", entry) {
			log.Tracef("Metadata (id: %v) is missing", id)
			queryResponse.UnknownIds = append(queryResponse.UnknownIds, id)
		}
	}

	// load all of the requested names
	for _, name := range queryRequest.Names {
		log.Tracef("Fetching metadata by name: %v | type: %v", name.Name, name.Type)

		entry, err := s.unpackByName(req.Context(), name.Name, name.Type, nil)
		if err != nil {
			handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by name (%v %v): %v", name.Type, name.Name, err))
			return
		}
		if !resolver.AddLoaded(name.Name, name.Type, entry) {
			log.Tracef("Metadata (name: %v | type: %v) is missing", name.Name, name.Type)
			queryResponse.UnknownNames = append(queryResponse.UnknownNames, api.QueryNameEntry{Name: name.Name, Type: name.Type})
		}
	}

	// check if the dependencies should be resolved as well
	if queryRequest.Resolve {
		for resolver.Continue() {
			for _, missing := range resolver.Open {
				log.Tracef("Fetching resolved metadata by name: %v | type: %v", missing.Name, missing.Type)

				// perform the actual fetch of the resource
				entry, err := s.unpackByName(req.Context(), missing.Name, missing.Type, nil)
				if err != nil {
					handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by name (%v %v): %v", missing.Type, missing.Name, err))
					return
				}

				// check if the entry could actually be resolved
				if !resolver.AddLoaded(missing.Name, missing.Type, entry) {
					log.Tracef("Resolved metadata (name: %v | type: %v) is missing", missing.Name, missing.Type)
					queryResponse.UnknownNames = append(queryResponse.UnknownNames, api.QueryNameEntry{Name: missing.Name, Type: missing.Type})
				}
			}
		}
	} else {
		resolver.Flush()
	}

	// write all resolved entries to the response
	for id, entry := range resolver.Entries {
		queryResponse.Metadata[id] = api.QueryMetadataEntry{
			Name:    entry.Info.Name,
			Type:    entry.Info.Type,
			Version: entry.Info.Version,
			Data:    entry.Raw,
		}
	}

	// send the query result as json encoded back
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	json.NewEncoder(resp).Encode(queryResponse)
}
func (s *Server) handleFetchId(req *http.Request, resp http.ResponseWriter, id string) {
	log.Tracef("Fetching metadata for [id: %v]", id)

	// validate the id formatting
	if !RegexHashCheck.MatchString(id) {
		handleBadRequest(resp, "malformed id (%v)", id)
		return
	}

	// query the store for the entry (ids are stored in lowercase)
	entry, err := s.unpackById(req.Context(), id)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by id: %v", err))
		return
	}

	// send the entry (will automatically account for not-found)
	handleSendEntry(resp, fmt.Sprintf("id (%v)", id), entry)
}
func (s *Server) handleFetchName(req *http.Request, resp http.ResponseWriter, kind, name string) {
	query := req.URL.Query()
	log.Tracef("Fetching metadata for [name: %v] [type: %v] [signer: %v]", name, kind, query.Get("signer"))
	var signer *string

	// validate the name and optional signer formatting
	if !RegexNameCheck.MatchString(name) {
		handleBadRequest(resp, "malformed name (%v)", name)
		return
	}
	if query.Has("signer") {
		value := strings.ToLower(query.Get("signer"))
		if !RegexHashCheck.MatchString(value) {
			handleBadRequest(resp, "malformed signer (%v)", value)
			return
		}
		signer = &value
	}

	// query the store for the entry
	entry, err := s.unpackByName(req.Context(), name, kind, signer)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by name: %v", err))
		return
	}

	// send the entry (will automatically account for not-found)
	handleSendEntry(resp, fmt.Sprintf("name (%v)", name), entry)
}

func (s *Server) unpackById(ctx context.Context, id string) (*MetadataFull, error) {
	info, err := s.index.ByID(ctx, strings.ToLower(id))
	if err != nil {
		return nil, err
	}
	return s.unpackEntry(ctx, info)
}
func (s *Server) unpackByName(ctx context.Context, name, kind string, signer *string) (*MetadataFull, error) {
	info, err := s.index.Latest(ctx, kind, name, signer)
	if err != nil {
		return nil, err
	}
	return s.unpackEntry(ctx, info)
}
func (s *Server) unpackEntry(ctx context.Context, info *store.EntryInfo) (*MetadataFull, error) {
	// check if the index does not know the entry
	if info == nil {
		return nil, nil
	}

	// fetch the blob referenced by the index entry
	raw, err := s.blobs.Get(ctx, info.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata blob (id %v): %w", info.Id, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("metadata blob (id %v) is referenced by the index but missing in the blob store", info.Id)
	}
	return UnpackMetadata(info, raw)
}
