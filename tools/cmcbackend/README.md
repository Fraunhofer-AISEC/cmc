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
GET    /latestresults                # Retrieve an overview of the latest result from each prover
GET    /devices                      # Retrieve all prover names
GET    /categories                   # Retrieve the configured categories and the default
```

## Categories

Categories separate independent deployments within the same database, so that the
frontend can show them as separate demos. They are declared in the config file:

```json
"defaultCategory": "demo",
"categories": [
    { "id": "demo", "label": "Attestation Demo" },
    { "id": "ids",  "label": "Industrial Data Space" }
]
```

Publishers select their category through the query parameter of the URL they post to,
for example `"publishResults": "http://localhost:8080/results?category=ids"`. Without
the parameter the default category is used, unknown categories are rejected.

All GET endpoints accept the same `?category=` parameter to filter their results.
Omitting it returns the entries of all categories.

`maxRows` and `maxRowsPerProver` apply to each category individually, so a busy
deployment cannot evict the provers of another one. Both limits take effect on
restart, also for existing databases. See
`example-setup/configs/cmcbackend-conf.json` for a complete example.

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
