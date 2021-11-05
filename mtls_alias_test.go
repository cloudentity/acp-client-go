package acpclient

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/cloudentity/acp-client-go/client/oauth2"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestMTLSAlias(t *testing.T) {
	gock.New("http://foo.com").
		Persist().
		Get("/openid-configuration").
		Reply(200).
		JSON([]byte(`{
		"authorization_endpoint": "http://foo.com/tid/aid/oauth2/authorize",
		"token_endpoint": "http://foo.com/tid/aid/oauth2/token",
		"userinfo_endpoint": "http://foo.com/tid/aid/userinfo",
		"introspection_endpoint": "http://foo.com/tid/aid/oauth2/introspect",
		"mtls_endpoint_aliases": {
			"token_endpoint": "http://foo.mtls.com/tid/aid/oauth2/token",
			"revocation_endpoint": "http://bar.mtls.com/tid/aid/oauth2/revoke",
			"introspection_endpoint": "http://baz.mtls.com/tid/aid/oauth2/introspect"
		}
	}`))
	issuer, err := url.Parse("http://foo.com/tid/aid")
	require.NoError(t, err)

	testCases := []struct {
		name   string
		config Config
		doTest func(*testing.T, Client)
	}{
		{
			name: "test that client uses mtls aliases when configured with cert and key",
			config: Config{
				ClientID:   "cid-1",
				IssuerURL:  issuer,
				HttpClient: &http.Client{},
				CertFile:   "test-data/certs/cert.pem",
				KeyFile:    "test-data/certs/key.pem",
			},
			doTest: func(t *testing.T, client Client) {
				_, err := client.Acp.Oauth2.Token(
					oauth2.NewTokenParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
				)
				require.Contains(t, err.Error(), "http://foo.mtls.com/tid/aid/oauth2/token")

				_, err = client.Acp.Oauth2.Introspect(
					oauth2.NewIntrospectParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
					nil,
				)
				require.Contains(t, err.Error(), "http://baz.mtls.com/tid/aid/oauth2/introspect")

				_, err = client.Acp.Oauth2.Revoke(
					oauth2.NewRevokeParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
					nil,
				)
				require.Contains(t, err.Error(), "http://bar.mtls.com/tid/aid/oauth2/revoke")
			},
		},

		{
			name: "test that client does not use mtls aliases when configured without cert and key",
			config: Config{
				ClientID:   "cid-1",
				IssuerURL:  issuer,
				HttpClient: &http.Client{},
				CertFile:   "",
				KeyFile:    "",
			},
			doTest: func(t *testing.T, client Client) {
				_, err := client.Acp.Oauth2.Token(
					oauth2.NewTokenParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
				)
				require.Contains(t, err.Error(), "http://foo.com/tid/aid/oauth2/token")

				_, err = client.Acp.Oauth2.Introspect(
					oauth2.NewIntrospectParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
					nil,
				)
				require.Contains(t, err.Error(), "http://foo.com/tid/aid/oauth2/introspect")

				_, err = client.Acp.Oauth2.Revoke(
					oauth2.NewRevokeParamsWithContext(context.Background()).
						WithTid(client.TenantID).
						WithAid(client.ServerID),
					nil,
				)
				require.Contains(t, err.Error(), "http://foo.com/tid/aid/oauth2/revoke")
			},
		},
	}

	for _, tc := range testCases {
		client, err := New(tc.config)
		require.NoError(t, err)
		tc.doTest(t, client)
	}

	gock.OffAll()
}
