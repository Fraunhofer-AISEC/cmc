# README

> :warning: **Note:** This is a simple, unsecure Proof-of-Concept implementation for demonstration purposes only

Monitoring server for managing attestation results and OCSF detection findings. The server
provides a simple HTTP REST API to store and retrieve attestation results and OCSF detection
findings from the CMC.

Results are stored in the `results` table and OCSF detection findings in the `ocsf_findings`
table, both in the same SQLite database file.

The server provides the following REST API:

**Attestation Results**
```sh
POST   /results                      # Insert a new attestation result
GET    /statistics                   # Retrieve attestation statistics (no result body)
GET    /results                      # Retrieve all attestation results
GET    /results/:name/latest         # Retrieve latest result from prover :name
GET    /resultsbyid/:id              # Retrieve a result by its SHA-256 :id
GET    /envelopes/:name              # Retrieve all result envelopes for prover :name
GET    /latestresults                # Retrieve the latest result from each prover
GET    /devices                      # Retrieve all prover names
```

**OCSF Detection Findings**
```sh
POST   /ocsf-detection-finding       # Insert a new OCSF Detection Finding [class 2004]
```

## Build

```sh
go build
```

## Test

Query all attestation results:

```sh
curl http://localhost:8080/results
```

Query latest result for a specific prover:

```sh
curl http://localhost:8080/results/<prover-name>/latest
```

Insert an attestation result:

```sh
curl http://localhost:8080/results \
    --include \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer <HEXSTRING>" \
    --request "POST" \
    --data @attestation-result.json
```

Insert an OCSF detection finding:

```sh
curl http://localhost:8080/ocsf-detection-finding \
    --include \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer <HEXSTRING>" \
    --request "POST" \
    --data @detection-finding.json
```
