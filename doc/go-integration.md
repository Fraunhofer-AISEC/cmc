# Integration

To integrate attestation into own projects, run the *cmcd* as a daemon on your system and replace
the go standard library `crypto/tls` or `net/http` package with the `cmc/attestedtls` or
`cmc/attestedhttp` package respectively. The API was kept as close as possible to the
original TLS / HTTP API, so that only some additional config options must be provided and many
data types, such as `net.Conn` (https://pkg.go.dev/net#Conn) can still be used.

In the following examples, error handling was omitted for simplicity. For the configurations,
see [configuration](./configuration.md).

## Attested TLS

### Client

```go
// Import the attested TLS package
import atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"

// Establish attested TLS client connection
conn, _ := atls.Dial("tcp", "localhost:4443", tlsConf,
    atls.WithCmcAddr("localhost:9955"),
    atls.WithCmcApi(CmcApi_Socket),
    // TODO Potentially more configuration options
)
defer conn.Close()

// Send data over the attested TLS connection
_, _ = conn.Write([]byte("Hello, World"))
```

### Server

```go
// Import the attested TLS package
import atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"

// Create server TLS configuration
tlsConf := &tls.Config{
    Certificates:  []tls.Certificate{cert},
    ClientAuth:    clientAuth,
    ClientCAs:     roots,
}

// Create CMC configuration (see configuration documentation)
conf := &CmcConfig{
    // ...
}

// Create an attested TLS listener
ln, _ := atls.Listen("tcp", "localhost:4443", tlsConf,
    atls.WithCmcAddr("localhost:9955"),
    atls.WithCmcApi(CmcApi_Socket),
    // TODO Potentially more configuration options
)
defer ln.Close()

for {
    // Accept connection and perform remote attestation
    conn, _ := ln.Accept()

    // Handle established connections
    go handle(conn)
}
```

## Attested HTTP

### Client

```go
// Import the attested HTTPS package
import ahttp "github.com/Fraunhofer-AISEC/cmc/attestedhttp"

// Create attested HTTPS transport
transport := &ahttp.Transport{
    IdleConnTimeout: 60 * time.Second,
    TLSClientConfig: tlsConfig,
    // Additional CMC configuration (see configuration documentation)
}

// Create attested HTTP client
client := &ahttp.Client{Transport: transport}

// Perform attested HTTPS GET request
resp, _ := client.Do("https://localhost:80/hello")
```

### Server

```go
// Import the attested HTTPS package
import ahttp "github.com/Fraunhofer-AISEC/cmc/attestedhttp"

// Create attested HTTP server
server := &ahttp.Server{
    Server: &http.Server{
        Addr:      addr,
        TLSConfig: tlsConfig,
    },
    // Additional CMC configuration (see configuration documentation)
}

// Use the golang net/http module functions to configure the server as usual
http.HandleFunc("/hello", handleRequest)

// Call the attested ListenAndServe method from the attested HTTP server
// to run the server
_ = server.ListenAndServe()
```