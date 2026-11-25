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

package server

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
	mux         *http.ServeMux
}

const (
	maxUploadSize   = 20_000_000
	maxQuerySize    = 1_000_000
	maxQueryEntries = 500
	serverTimeout   = 60 * time.Second

	// origin of entries, which have been uploaded directly to this instance
	originLocal = "local"
)

// Create a new RVPS server operating on the given index and blob store
// (CAs must be provided and only uploads signed by them are trusted)
func New(index store.Index, blobs store.BlobStore, metadataCAs []*x509.Certificate) (*Server, error) {
	if index == nil || blobs == nil {
		return nil, errors.New("index and blob store are required")
	}
	if len(metadataCAs) == 0 {
		return nil, errors.New("trusted metadata certificates are required")
	}

	s := &Server{index: index, blobs: blobs, metadataCAs: metadataCAs, mux: http.NewServeMux()}

	// setup the router (fixed paths take precedence over the [/<type or alias>/<name>] paths used to fetch metadata by name)
	s.mux.HandleFunc("GET /list", s.handleEnumerate)
	s.mux.HandleFunc("POST /metadata", s.handleUpload)
	s.mux.HandleFunc("POST /query", s.handleQuery)
	s.mux.HandleFunc("GET /metadata/{id}", s.handleFetchId)
	s.mux.HandleFunc("GET /{kind}/{name}", s.handleFetchName)
	s.mux.HandleFunc("/", handleNotFound)
	return s, nil
}

// Handler returns the HTTP handler serving the RVPS API
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Serve provides the RVPS API via HTTPS on addr until the context is cancelled
func (s *Server) Serve(ctx context.Context, addr string, tlsKey crypto.PrivateKey, tlsCaChain []*x509.Certificate) error {
	// the service is only provided via tls
	if tlsKey == nil || len(tlsCaChain) == 0 {
		return errors.New("tls key and certificate chain are required")
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
		Handler:      s.Handler(),
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

func handleNotFound(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(resp, "Resource [%v] not found", req.URL.Path)
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
func handleSendEntry(resp http.ResponseWriter, what string, entry *MetadataBundle) {
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
func handleReadUpload(req *http.Request, resp http.ResponseWriter, contentType string, maxSize int64) []byte {
	// check if the content type needs to be validated
	if contentType != "" {
		if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), contentType) {
			handleBadRequest(resp, "request payload of type [%v] expected", contentType)
			return nil
		}
	}

	// read the body and ensure its not too large
	body, err := io.ReadAll(http.MaxBytesReader(resp, req.Body, maxSize))
	if err == nil {
		return body
	}
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		handleBadRequest(resp, "failed to read body: %v", err)
		return nil
	}

	// notify the client about the upload constraints
	log.Warnf("Rejecting too large upload of more than %v bytes", maxSize)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusRequestEntityTooLarge)
	fmt.Fprintf(resp, "Body exceeds the maximum size of %v bytes", maxSize)
	return nil
}
func (s *Server) handleEnumerate(resp http.ResponseWriter, req *http.Request) {
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
	infos := make([]api.MetadataInfo, 0, len(entries))
	for _, entry := range entries {
		infos = append(infos, makeApiEntry(entry))
	}

	// send the enumeration information as json encoded back
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	json.NewEncoder(resp).Encode(infos)
}
func (s *Server) handleUpload(resp http.ResponseWriter, req *http.Request) {
	log.Tracef("Uploading metadata")

	// read the request body (unknown content type) and ensure its not empty
	body := handleReadUpload(req, resp, "", maxUploadSize)
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

	// setup the load-parameter (will be discarded, if the entry is not actually inserted)
	entry.Created = time.Now().UTC().Format(time.RFC3339)
	entry.Origin = originLocal

	// write the blob first, as blob without index is harmless, but an index must point at a valid blob
	if err := s.blobs.Put(req.Context(), entry.Id, body); err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to store metadata blob: %v", err))
		return
	}
	inserted, err := s.index.Insert(req.Context(), *entry)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to insert metadata: %v", err))
		return
	}

	// check if the data were already in the index (not an error, as metadata are immutable and addressed by their content)
	result := "inserted"
	if !inserted {
		log.Infof("Metadata %v %v with id %v already exists", entry.Type, entry.Name, entry.Id)
		result = "already exists"
	} else {
		log.Infof("Inserted %v %v version %v (id %v) into the index", entry.Type, entry.Name, entry.Version, entry.Id)
	}

	// return the successful insertion
	resp.Header().Set("X-Metadata-Id", entry.Id)
	resp.Header().Set("X-Metadata-Name", entry.Name)
	resp.Header().Set("X-Metadata-Type", entry.Type)
	resp.Header().Set("X-Metadata-Version", entry.Version)
	resp.Header().Set("X-Metadata-Signer", entry.Signer)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	fmt.Fprintf(resp, "Metadata %v (id: %v) %v", entry.Name, entry.Id, result)
}
func (s *Server) handleQuery(resp http.ResponseWriter, req *http.Request) {
	log.Trace("Querying metadata")

	// read the request body and parse it
	body := handleReadUpload(req, resp, "application/json", maxQuerySize)
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
	if count := len(queryRequest.Ids) + len(queryRequest.Names); count > maxQueryEntries {
		handleBadRequest(resp, "too many ids and names requested (%v) only %v supported", count, maxQueryEntries)
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
		if name.Signer != "" {
			if !RegexHashCheck.MatchString(name.Signer) {
				handleBadRequest(resp, "malformed signer (%v) for %v", name.Signer, name.Name)
				return
			}
			queryRequest.Names[i].Signer = strings.ToLower(name.Signer)
		}
	}
	queryResponse, resolver := &api.QueryResponse{
		Version:  api.Version,
		Metadata: make(map[string]api.QueryMetadataEntry),
	}, NewMetadataResolver()

	// load all of the requested ids
	for _, id := range queryRequest.Ids {
		log.Tracef("Fetching metadata by id: %v", id)

		entry, err := s.unpackById(req.Context(), id, queryRequest.Resolve)
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
		log.Tracef("Fetching metadata by name: %v | type: %v | signer: %v", name.Name, name.Type, name.Signer)

		// check if the lookup should be restricted to a signer
		var signer *string
		if name.Signer != "" {
			signer = &name.Signer
		}
		entry, err := s.unpackByName(req.Context(), name.Name, name.Type, signer, queryRequest.Resolve)
		if err != nil {
			handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by name (%v %v): %v", name.Type, name.Name, err))
			return
		}
		if !resolver.AddLoaded(name.Name, name.Type, entry) {
			log.Tracef("Metadata (name: %v | type: %v) is missing", name.Name, name.Type)
			queryResponse.UnknownNames = append(queryResponse.UnknownNames, name)
		}
	}

	// check if the dependencies should be resolved as well
	if queryRequest.Resolve {
		for resolver.Continue() {
			for _, missing := range resolver.Open {
				log.Tracef("Fetching resolved metadata by name: %v | type: %v", missing.Name, missing.Type)

				// perform the actual fetch of the resource
				entry, err := s.unpackByName(req.Context(), missing.Name, missing.Type, nil, true)
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
			Signer:  entry.Info.Signer,
			Data:    entry.Raw,
		}
	}

	// send the query result as json encoded back
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	json.NewEncoder(resp).Encode(queryResponse)
}
func (s *Server) handleFetchId(resp http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	log.Tracef("Fetching metadata for [id: %v]", id)

	// validate the id formatting
	if !RegexHashCheck.MatchString(id) {
		handleBadRequest(resp, "malformed id (%v)", id)
		return
	}

	// query the store for the entry (ids are stored in lowercase)
	entry, err := s.unpackById(req.Context(), id, false)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by id: %v", err))
		return
	}

	// send the entry (will automatically account for not-found)
	handleSendEntry(resp, fmt.Sprintf("id (%v)", id), entry)
}
func (s *Server) handleFetchName(resp http.ResponseWriter, req *http.Request) {
	query, name := req.URL.Query(), req.PathValue("name")

	// only the metadata types and their aliases are valid as first path element
	kind, ok := ResolveMetadataType(req.PathValue("kind"))
	if !ok {
		handleNotFound(resp, req)
		return
	}
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
	entry, err := s.unpackByName(req.Context(), name, kind, signer, false)
	if err != nil {
		handleInternalError(resp, fmt.Sprintf("failed to fetch metadata by name: %v", err))
		return
	}

	// send the entry (will automatically account for not-found)
	handleSendEntry(resp, fmt.Sprintf("name (%v)", name), entry)
}

func (s *Server) unpackById(ctx context.Context, id string, parse bool) (*MetadataBundle, error) {
	info, err := s.index.ByID(ctx, strings.ToLower(id))
	if err != nil {
		return nil, err
	}
	return s.unpackEntry(ctx, info, parse)
}
func (s *Server) unpackByName(ctx context.Context, name, kind string, signer *string, parse bool) (*MetadataBundle, error) {
	info, err := s.index.Latest(ctx, kind, name, signer)
	if err != nil {
		return nil, err
	}
	return s.unpackEntry(ctx, info, parse)
}
func (s *Server) unpackEntry(ctx context.Context, info *store.EntryInfo, parse bool) (*MetadataBundle, error) {
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
	return UnpackMetadata(info, raw, parse)
}
func makeApiEntry(info store.EntryInfo) api.MetadataInfo {
	return api.MetadataInfo{
		Id:      info.Id,
		Type:    info.Type,
		Name:    info.Name,
		Version: info.Version,
		Signer:  info.Signer,
		Created: info.Created,
		Origin:  info.Origin,
		Format:  info.Format,
	}
}
