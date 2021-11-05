package acpclient

import (
	"net/http"
	"net/url"

	"github.com/cloudentity/acp-client-go/models"
	openapiRuntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"golang.org/x/oauth2/clientcredentials"
)

type HTTPRuntime struct {
	cfg        Config
	issuerHost string
	mtlsHosts  MTLSEndpointAliaseHosts
	rt         *httptransport.Runtime
}

func NewHTTPRuntime(cfg Config, cc clientcredentials.Config, httpClient *http.Client, mtlsHosts MTLSEndpointAliaseHosts) *HTTPRuntime {
	return &HTTPRuntime{
		cfg:        cfg,
		issuerHost: cfg.IssuerURL.Host,
		mtlsHosts:  mtlsHosts,
		rt: httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			"/",
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, httpClient),
		),
	}
}

func (m *HTTPRuntime) Submit(operation *openapiRuntime.ClientOperation) (interface{}, error) {
	if m.cfg.IsTLS() {
		switch operation.ID {
		case "token":
			m.rt.Host = m.mtlsHosts.TokenEndpointHost
		case "introspect":
			m.rt.Host = m.mtlsHosts.IntrospectionEndpointHost
		case "revoke":
			m.rt.Host = m.mtlsHosts.RevocationEndpointHost
		default:
			m.rt.Host = m.issuerHost
		}
	}

	return m.rt.Submit(operation)
}

type MTLSEndpointAliaseHosts struct {
	IntrospectionEndpointHost string
	RevocationEndpointHost    string
	TokenEndpointHost         string
}

func getMTLSAliasHosts(wellknown models.WellKnown) (MTLSEndpointAliaseHosts, error) {
	var (
		hosts MTLSEndpointAliaseHosts
		url   *url.URL
		err   error
	)

	if url, err = url.Parse(wellknown.MtlsEndpointAliases.IntrospectionEndpoint); err != nil {
		return hosts, err
	}
	hosts.IntrospectionEndpointHost = url.Host

	if url, err = url.Parse(wellknown.MtlsEndpointAliases.RevocationEndpoint); err != nil {
		return hosts, err
	}
	hosts.RevocationEndpointHost = url.Host

	if url, err = url.Parse(wellknown.MtlsEndpointAliases.TokenEndpoint); err != nil {
		return hosts, err
	}
	hosts.TokenEndpointHost = url.Host

	return hosts, nil
}
