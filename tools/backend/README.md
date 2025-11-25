# README

> :warning: **Note:** This is a simple, unsecure Proof-of-Concept implementation for demonstration purposes only

Monitoring server for managing attestation results. The server provides a simple HTTP REST API to
store and retrieve attestation results from the CMC.

The server provides the following REST API:
```sh
POST   /results                 # Inserts a new result
GET    /statistics              # Retrieve attestation statistics
GET    /results                 # Retrieves all attestation results
GET    /results/:name/latest    # Retrieves latest result from the prover :name
GET    /resultsbyid/:id         # Retrieves a result by its :id
GET    /envelopes/:name         # Retrieves all result envelopes containing the results from the prover :name
GET    /latestresults           # Retrieves all latest results from all provers
GET    /devices                 # Retrieves all prover names
```

## Build

```sh
go build
```

## Test

Query all devices:

```sh
curl http://localhost:8080/results
```

Query single device by ID:

```sh
curl http://localhost:8080/results/<device-name>
```

Add new device with:

```sh
curl http://localhost:8080/results \
    --include \
    --header "Content-Type: application/json" \
    --request "POST" \
    --data @test/attestation-result.json
```
