// Copyright (c) 2025 Fraunhofer AISEC
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
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type server struct {
	addr  string
	db    *Db
	token []byte
}

func newServer(c *config) server {
	db, err := NewDb(c.Db, "results", c.MaxRowsPerProver, c.MaxRows)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	var token []byte
	if c.Token != "" {
		token, err = os.ReadFile(c.Token)
		if err != nil {
			log.Fatalf("Failed to read token file: %v", err)
		}
	}

	return server{
		addr:  c.Addr,
		db:    db,
		token: token,
	}
}

func (s *server) handleGetStatistics(c *gin.Context) {
	getStatistics(c, s.db)
}

func (s *server) handleGetResults(c *gin.Context) {
	getResults(c, s.db)
}

func (s *server) handlePostResult(c *gin.Context) {
	postResult(c, s.db, s.token)
}

func (s *server) handleGetEnvelopesByName(c *gin.Context) {
	getEnvelopesByName(c, s.db)
}

func (s *server) handleGetLatestResult(c *gin.Context) {
	getLatestResult(c, s.db)
}

func (s *server) handleGetLatestResults(c *gin.Context) {
	getLatestResults(c, s.db)
}

func (s *server) handleGetResultById(c *gin.Context) {
	getResultById(c, s.db)
}

func (s *server) handleGetDevices(c *gin.Context) {
	getDevices(c, s.db)
}

func (s *server) serve() {
	defer s.db.Close()

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{"GET", "POST"},
		ExposeHeaders: []string{"Content-Length"},
	}))

	router.GET("/statistics", s.handleGetStatistics)
	router.GET("/results", s.handleGetResults)
	router.POST("/results", s.handlePostResult)
	router.GET("/envelopes/:name", s.handleGetEnvelopesByName)
	router.GET("/results/:name/latest", s.handleGetLatestResult)
	router.GET("/resultsbyid/:id", s.handleGetResultById)
	router.GET("/latestresults", s.handleGetLatestResults)
	router.GET("/devices", s.handleGetDevices)

	router.Run(s.addr)
}

// getStatistics retrieves the headers of all results for generic evaluation
func getStatistics(c *gin.Context, db *Db) {

	log.Trace("in GET /statistics")

	// Query results from database
	results, err := db.GetAllStatistics()
	if err != nil {
		msg := fmt.Sprintf("failed to retrieve statistics: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	// Send back results
	c.JSON(http.StatusOK, results)

	log.Tracef("Finished returning %v result statistics", len(results))
}

// getResults responds with the list of all results as JSON
func getResults(c *gin.Context, db *Db) {

	log.Trace("in GET /results")

	// Query results from database
	results, err := db.GetAllResults()
	if err != nil {
		msg := fmt.Sprintf("failed to retrieve results: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	// Send back results
	c.JSON(http.StatusOK, results)

	log.Tracef("Finished returning %v results", len(results))
}

// getEnvelopesByName responds with the envelopes (without result)
func getEnvelopesByName(c *gin.Context, db *Db) {

	name, err := getName(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("%v", err)})
	}

	// Get device from database
	results, err := db.GetEnvelopesByProver(name)
	if err != nil {
		msg := fmt.Sprintf("Failed to retrieve results: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	if len(results) == 0 {
		msg := fmt.Sprintf("No results for prover %v", name)
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": msg})
		log.Debug(msg)
		return
	}

	c.IndentedJSON(http.StatusOK, results)
}

// getLatestResults returns a list of the latest result of each device
func getLatestResults(c *gin.Context, db *Db) {

	log.Trace("in GET /latestresults")

	// Query results from database
	results, err := db.GetLatestResults()
	if err != nil {
		msg := fmt.Sprintf("failed to retrieve latest results: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	log.Trace("Returning latest results..")

	// Send back results
	c.JSON(http.StatusOK, results)

	log.Tracef("Finished returning %v latest results", len(results))
}

// getLatestResult responds with the latest result for the specified device
func getLatestResult(c *gin.Context, db *Db) {

	name, err := getName(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("%v", err)})
	}

	// Get latest result from database
	result, err := db.GetLatestResult(name)
	if err != nil {
		msg := fmt.Sprintf("Failed to retrieve result: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	if len(result) == 0 {
		msg := fmt.Sprintf("Failed to find result ID %v", name)
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": msg})
		log.Debug(msg)
		return
	} else if len(result) > 1 {
		msg := fmt.Sprintf("Invalid number of results %v for %v", len(result), name)
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": msg})
		log.Debug(msg)
		return
	}

	c.JSON(http.StatusOK, result[0])

}

// postResult adds a result from JSON
func postResult(c *gin.Context, db *Db, token []byte) {

	err := authorize(c.Request, token)
	if err != nil {
		msg := fmt.Sprintf("Unauthorized request: %v", err)
		log.Warnf("%v", msg)
		c.IndentedJSON(http.StatusUnauthorized, gin.H{"message": msg})
		return
	}

	res := new(any)

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		msg := fmt.Sprintf("Failed to read body: %v", err)
		c.IndentedJSON(http.StatusBadRequest, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	// Store device in database
	err = db.InsertResult(body)
	if err != nil {
		msg := fmt.Sprintf("Failed to insert data into DB: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	c.JSON(http.StatusCreated, res)
}

// getResultById gets a result by its ID
func getResultById(c *gin.Context, db *Db) {

	id, err := getId(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("%v", err)})
	}

	// Get latest result from database
	result, err := db.GetResultById(id)
	if err != nil {
		msg := fmt.Sprintf("Failed to retrieve result: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	if len(result) != 1 {
		msg := fmt.Sprintf("Invalid number of results %v for id %v", len(result), id)
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": msg})
		log.Debug(msg)
		return
	}

	c.JSON(http.StatusOK, result[0])
}

// getDevices returns a list of all devices for which there is a report stored in the database
func getDevices(c *gin.Context, db *Db) {

	// Get device names from database
	result, err := db.GetDeviceNames()
	if err != nil {
		msg := fmt.Sprintf("Failed to retrieve device names: %v", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"message": msg})
		log.Warn(msg)
		return
	}

	if len(result) == 0 {
		msg := "No device names found"
		c.IndentedJSON(http.StatusNotFound, gin.H{"message": msg})
		log.Debug(msg)
		return
	}

	c.JSON(http.StatusOK, result)
}

func authorize(req *http.Request, refToken []byte) error {

	// Authorization is optional and must be configured
	if refToken == nil {
		return nil
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("missing or invalid authorization header")
	}

	presentedToken := strings.TrimPrefix(authHeader, "Bearer ")
	presentedToken = strings.TrimSpace(presentedToken)

	if !strings.EqualFold(string(refToken), presentedToken) {
		return fmt.Errorf("failed to verify authorization token")
	}

	return nil
}

func getId(c *gin.Context) (string, error) {
	id := c.Param("id")
	idCheck := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if !idCheck.MatchString(id) {
		msg := "id must be a valid hex string"
		log.Warn(msg)
		return "", fmt.Errorf("%v", msg)
	}
	return id, nil
}

func getName(c *gin.Context) (string, error) {
	name := c.Param("name")
	nameCheck := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !nameCheck.MatchString(name) {
		msg := "name must be URL-safe (A-Z a-z 0-9 . _ ~ -)"
		log.Warn(msg)
		return "", fmt.Errorf("%v", msg)
	}
	return name, nil
}
