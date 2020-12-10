package acpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/cloudentity/acp-client-go/client"
	o2 "github.com/cloudentity/acp-client-go/client/oauth2"
	"github.com/cloudentity/acp-client-go/models"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Client provides a client to the ACP API
type Client struct {
	*client.Acp
	c *http.Client

	// Client configuration
	Config Config

	// Tenant id read from the IssuerURL
	TenantID string

	// Authorization server id read from the IssuerURL
	ServerID string
}

// ACP client configuration
type Config struct {
	// ClientID is the application's ID.
	ClientID string `json:"client_id"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to redirect users after authentication.
	RedirectURL *url.URL `json:"redirect_url"`

	// IssuerURL is the authorization server's url
	// example: https://localhost:8443/default/default
	IssuerURL *url.URL `json:"issuer_url"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes"`

	// Path to the file with private key for signing request object.
	RequestObjectSigningKeyFile string `json:"request_object_signing_key_file"`

	// Default HttpClient timeout.
	// Ignored if HttpClient is provided.
	Timeout time.Duration `json:"timeout"`

	// Optional path to the file with certificate for tls authentication.
	// Ignored if HttpClient is provided.
	CertFile string `json:"cert_file"`

	// Optional path to the file with private key for tls authentication.
	// Ignored if HttpClient is provided.
	KeyFile string `json:"key_file"`

	// Optional path to the file with root CAs.
	// Ignored if HttpClient is provided.
	RootCA string `json:"root_ca"`

	// HttpClient is the client to use. Default will be used if not provided.
	HttpClient *http.Client `json:"-"`
}

func (c *Config) newHTTPClient() (*http.Client, error) {
	var (
		pool *x509.CertPool
		cert tls.Certificate
		data []byte
		err  error
	)

	if cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		return nil, errors.Wrapf(err, "failed to read certificate and private key")
	}

	if pool, err = x509.SystemCertPool(); err != nil {
		return nil, errors.Wrapf(err, "failed to read system root CAs")
	}

	if c.RootCA != "" {
		if data, err = ioutil.ReadFile(c.RootCA); err != nil {
			return nil, fmt.Errorf("failed to read http client root ca: %w", err)
		}

		pool.AppendCertsFromPEM(data)
	}

	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			ResponseHeaderTimeout: c.Timeout,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
		},
	}, nil
}

// Create a new ACP client instance based on config.
func New(cfg Config) (c Client, err error) {
	if cfg.ClientID == "" {
		return c, errors.New("client_id is missing")
	}

	paths := strings.Split(cfg.IssuerURL.Path, "/")

	if len(paths) < 2 {
		return c, errors.New("invalid issuer url")
	}

	c.TenantID = paths[1]
	c.ServerID = paths[2]

	if c.c, err = cfg.newHTTPClient(); err != nil {
		return c, err
	}

	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		TokenURL:     fmt.Sprintf("%s/oauth2/token", cfg.IssuerURL),
	}

	c.Acp = client.New(httptransport.NewWithClient(
		cfg.IssuerURL.Host,
		"/",
		[]string{cfg.IssuerURL.Scheme},
		cc.Client(context.WithValue(context.Background(), oauth2.HTTPClient, c.c)),
	), nil)

	c.Config = cfg

	return c, nil
}

type Token struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
}

// CSRS contains state, nonce and/or PKCEverifier which are used
// to mitigate replay attacts and cross-site request forgery.
type CSRF struct {
	// State is an opaque value used by the client to maintain
	// state between the request and callback.  The authorization
	// server includes this value when redirecting the user-agent back
	// to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery
	State string

	// Nonce is a string value used to associate a client session with
	// an ID Token, and to mitigate replay attacks
	Nonce string

	// PKCE code verifier
	Verifier string
}

type AuthorizeOption interface {
	apply(*Client, url.Values, *CSRF) error
}

type authorizeOptionFn struct {
	fn func(*Client, url.Values, *CSRF) error
}

func (o *authorizeOptionFn) apply(c *Client, v url.Values, csrf *CSRF) error {
	return o.fn(c, v, csrf)
}

func authorizeHandler(fn func(*Client, url.Values, *CSRF) error) AuthorizeOption {
	return &authorizeOptionFn{fn: fn}
}

func WithPKCE() AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		// TODO generate verifier and inject code challange

		return nil
	})
}

func WithOpenbankingIntentID(intentID string, acr []string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		// TODO create and sign request object

		return nil
	})
}

func (c *Client) AuthorizeURL(options ...AuthorizeOption) (authorizeURL string, csrf CSRF, err error) {
	values := url.Values{
		"response_type": {"code"},
		"client_id":     {c.Config.ClientID},
	}

	if c.Config.RedirectURL != nil {
		values.Set("redirect_uri", c.Config.RedirectURL.String())
	}

	if len(c.Config.Scopes) > 0 {
		values.Set("scope", strings.Join(c.Config.Scopes, " "))
	}

	for _, o := range options {
		o.apply(c, values, &csrf)
	}

	return fmt.Sprintf("%s/oauth2/authorize?%s", c.Config.IssuerURL.String(), values.Encode()), csrf, nil
}

func (c *Client) Exchange(code string, csrf CSRF) (token Token, err error) {
	// TODO exchange and check stage/nonce/verifier

	return token, nil
}

func (c *Client) IntrospectToken(token string) (*models.IntrospectResponse, error) {
	var (
		resp *o2.IntrospectOK
		err  error
	)

	if resp, err = c.Oauth2.Introspect(o2.NewIntrospectParams().
		WithTid(c.TenantID).
		WithAid(c.ServerID).
		WithToken(&token), nil); err != nil {
		return nil, err
	}

	return resp.Payload, nil
}
