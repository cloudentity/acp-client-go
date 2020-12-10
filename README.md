# Cloudentity ACP OpenAPI Go Client

This repository contains a generated OpenAPI client for [Go](https://golang.org/)

It's generated from OpenAPI 2.0 specification.

## Sample usage

### Client secret basic or client secret post authentication

```go
import "github.com/cloudentity/acp-client-go"

var client = acpclient.New(acpclient.Config{
    ClientID:     "your-clients-id",
    ClientSecret: "your-clients-secret",
    IssuerURL:    "https://localhost:8443/default/default",
    Scopes:       []string{"introspect_tokens"},
})
```

### TLS client authentication

``` go
import "github.com/cloudentity/acp-client-go"

var client = acpclient.New(acpclient.Config{
    ClientID:  "your-clients-id",
    IssuerURL: "https://localhost:8443/default/default",
    CertFile:  "./cert.pem",
    KeyFile:   "./key.pem",
    RootCA:    "./ca.pem",
    Scopes:    []string{"accounts"},
})
```
