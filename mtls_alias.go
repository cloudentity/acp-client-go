package acpclient

import (
	"net/url"

	"github.com/cloudentity/acp-client-go/models"
	openapiRuntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
)

type MTLSAliasRuntime struct {
	originalHost string
	mtlsHosts    MTLSEndpointAliaseHosts
	*httptransport.Runtime
}

func (m *MTLSAliasRuntime) Submit(operation *openapiRuntime.ClientOperation) (interface{}, error) {
	switch operation.ID {
	case "token":
		m.Runtime.Host = m.mtlsHosts.TokenEndpointHost
	default:
		m.Runtime.Host = m.originalHost
	}

	return m.Runtime.Submit(operation)
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
