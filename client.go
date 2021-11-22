package acpclient

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	obbrConsents "github.com/cloudentity/acp-client-go/clients/openbankingBR/consents/client"
	obbrPayments "github.com/cloudentity/acp-client-go/clients/openbankingBR/payments/client"

	obukAccounts "github.com/cloudentity/acp-client-go/clients/openbankingUK/accounts/client"
	obukPayments "github.com/cloudentity/acp-client-go/clients/openbankingUK/payments/client"

	o2Client "github.com/cloudentity/acp-client-go/clients/oauth2/client"
	o2Params "github.com/cloudentity/acp-client-go/clients/oauth2/client/oauth2"
	o2models "github.com/cloudentity/acp-client-go/clients/oauth2/models"

	adminClient "github.com/cloudentity/acp-client-go/clients/admin/client"
	developerClient "github.com/cloudentity/acp-client-go/clients/developer/client"
	publicClient "github.com/cloudentity/acp-client-go/clients/public/client"
	rootClient "github.com/cloudentity/acp-client-go/clients/root/client"
	systemClient "github.com/cloudentity/acp-client-go/clients/system/client"
	webClient "github.com/cloudentity/acp-client-go/clients/web/client"

	"github.com/dgrijalva/jwt-go"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/pkg/errors"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	NonceLength    = 20
	StateLength    = 8
	VerifierLength = 43
)

type OpenbankingUK struct {
	Accounts *obukAccounts.OpenbankingUKClient
	Payments *obukPayments.OpenbankingUKClient
}

type OpenbankingBrasil struct {
	Consents *obbrConsents.OpenbankingBRClient
	Payments *obbrPayments.OpenbankingBRClient
}

type Oauth2 struct {
	*o2Client.Acp
}

type Admin struct {
	*adminClient.Acp
}

type Developer struct {
	*developerClient.Acp
}

type Public struct {
	*publicClient.Acp
}

type System struct {
	*systemClient.Acp
}

type Web struct {
	*webClient.Acp
}

type Root struct {
	*rootClient.Acp
}

// Client provides a client to the ACP API
type Client struct {
	Oauth2    *Oauth2
	Admin     *Admin
	Developer *Developer
	Public    *Public
	System    *System
	Web       *Web
	Root      *Root

	*OpenbankingUK
	*OpenbankingBrasil

	c          *http.Client
	signingKey interface{}

	// Client configuration
	Config Config

	// Tenant id read from the IssuerURL
	TenantID string

	// Authorization server id read from the IssuerURL
	ServerID string

	// Base path read from the IssuerURL
	BasePath string
}

// ACP client configuration
type Config struct {
	// ClientID is the application's ID.
	ClientID string `json:"client_id"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to redirect users after authentication.
	RedirectURL *url.URL `json:"redirect_url"`

	// IssuerURL is the authorization server's url.
	// example: https://localhost:8443/default/default
	IssuerURL *url.URL `json:"issuer_url"`

	// TokenURL is the authorization server's token url.
	// Optional if issuerURL provided
	TokenURL *url.URL

	// AuthorizeURL is the authorization server's authorize url.
	// Optional if issuerURL provided
	AuthorizeURL *url.URL

	// UserinfoURL is the authorization server's userinfo url.
	// Optional if issuerURL provided
	UserinfoURL *url.URL

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes"`

	// Path to the file with private key for signing request object.
	RequestObjectSigningKeyFile string `json:"request_object_signing_key_file"`

	// Optional request object expiration time
	// If not provided, it will be se to 1 minute
	RequestObjectExpiration *time.Duration `json:"request_object_expiration"`

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

	// Routing mode
	RoutingMode string `json:"routing_mode"`
}

func (c *Config) GetTokenURL() string {
	if c.TokenURL != nil {
		return c.TokenURL.String()
	}

	return fmt.Sprintf("%s/oauth2/token", c.IssuerURL.String())
}

func (c *Config) GetAuthorizeURL() string {
	if c.AuthorizeURL != nil {
		return c.AuthorizeURL.String()
	}

	return fmt.Sprintf("%s/oauth2/authorize", c.IssuerURL.String())
}

func (c *Config) GetUserinfoURL() string {
	if c.UserinfoURL != nil {
		return c.UserinfoURL.String()
	}

	return fmt.Sprintf("%s/userinfo", c.IssuerURL.String())
}

func (c *Client) discoverEndpoints(issuerURL string) error {
	var (
		b             []byte
		wellKnown     o2models.WellKnown
		resp          *http.Response
		tokenEndpoint string
		err           error
	)

	if resp, err = c.c.Get(fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)); err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if b, err = ioutil.ReadAll(resp.Body); err != nil {
			return errors.WithMessagef(err, "unable to read response body from well-known endpoint with status %d", resp.StatusCode)
		}
		return errors.WithMessage(errors.New(string(b)), "unable to get well-known endpoints")
	}

	if err = json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return err
	}

	tokenEndpoint = wellKnown.TokenEndpoint
	if c.Config.CertFile != "" && c.Config.KeyFile != "" {
		if wellKnown.MtlsEndpointAliases != nil && wellKnown.MtlsEndpointAliases.TokenEndpoint != "" {
			tokenEndpoint = wellKnown.MtlsEndpointAliases.TokenEndpoint
		}
	}

	if c.Config.TokenURL, err = url.Parse(tokenEndpoint); err != nil {
		return err
	}

	if c.Config.AuthorizeURL, err = url.Parse(wellKnown.AuthorizationEndpoint); err != nil {
		return err
	}

	if c.Config.UserinfoURL, err = url.Parse(wellKnown.UserinfoEndpoint); err != nil {
		return err
	}

	return nil
}

func (c *Config) newHTTPClient() (*http.Client, error) {
	var (
		pool  *x509.CertPool
		cert  tls.Certificate
		certs = []tls.Certificate{}
		data  []byte
		err   error
	)

	if c.CertFile != "" && c.KeyFile != "" {
		if cert, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
			return nil, errors.Wrapf(err, "failed to read certificate and private key")
		}

		certs = append(certs, cert)
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
				Certificates: certs,
			},
		},
	}, nil
}

// Create a new ACP client instance based on config.
func New(cfg Config) (c Client, err error) {
	if cfg.ClientID == "" {
		return c, errors.New("client_id is missing")
	}

	if cfg.IssuerURL == nil {
		return c, errors.New("issuer_url is missing")
	}

	// default routing mode
	if cfg.RoutingMode == "" {
		paths := strings.Split(cfg.IssuerURL.Path, "/")

		if len(paths) < 2 {
			return c, errors.New("invalid issuer url")
		}

		lastIdx := len(paths) - 1

		c.TenantID = paths[lastIdx-1]
		c.ServerID = paths[lastIdx]

		c.BasePath = strings.Join(paths[:lastIdx-2], "/")

		if c.BasePath == "/" {
			c.BasePath = ""
		}
	}

	if cfg.HttpClient == nil {
		if c.c, err = cfg.newHTTPClient(); err != nil {
			return c, err
		}
	} else {
		c.c = cfg.HttpClient
	}

	if err = c.discoverEndpoints(cfg.IssuerURL.String()); err != nil {
		return c, err
	}

	if cfg.RequestObjectSigningKeyFile != "" {
		var bs []byte

		if bs, err = ioutil.ReadFile(cfg.RequestObjectSigningKeyFile); err != nil {
			return c, errors.Wrapf(err, "failed to read request object signing key")
		}

		block, _ := pem.Decode(bs)

		if c.signingKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return c, errors.Wrapf(err, "failed to parse request object signing key")
		}
	}

	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		TokenURL:     cfg.GetTokenURL(),
	}

	c.Oauth2 = &Oauth2{
		Acp: o2Client.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/%s/%s", c.TenantID, c.ServerID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.Admin = &Admin{
		Acp: adminClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/api/admin/%s", c.TenantID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.Developer = &Developer{
		Acp: developerClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/api/developer/%s/%s", c.TenantID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.Public = &Public{
		Acp: publicClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/%s/%s", c.TenantID, c.ServerID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.Root = &Root{
		Acp: rootClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.System = &System{
		Acp: systemClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/api/system/%s", c.TenantID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.Web = &Web{
		Acp: webClient.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			fmt.Sprintf(c.BasePath+"/%s", c.TenantID),
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	apiPrefix := fmt.Sprintf(c.BasePath+"/%s/%s", c.TenantID, c.ServerID)

	c.OpenbankingUK = &OpenbankingUK{
		Accounts: obukAccounts.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukAccounts.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),

		Payments: obukPayments.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukPayments.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

	c.OpenbankingBrasil = &OpenbankingBrasil{
		Consents: obbrConsents.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukAccounts.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),

		Payments: obbrPayments.New(httptransport.NewWithClient(
			cfg.IssuerURL.Host,
			apiPrefix+obukPayments.DefaultBasePath,
			[]string{cfg.IssuerURL.Scheme},
			NewAuthenticator(cc, c.c),
		).WithOpenTracing(), nil),
	}

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

// CSRF contains state, nonce and/or PKCEverifier which are used
// to mitigate replay attacks and cross-site request forgery.
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

type ClaimRequests struct {
	Userinfo map[string]*ClaimRequest `json:"userinfo"`
	IDToken  map[string]*ClaimRequest `json:"id_token"`
}

type ClaimRequest struct {
	Essential bool     `json:"essential"`
	Value     string   `json:"value"`
	Values    []string `json:"values"`
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
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) (err error) {
		if csrf.Verifier, err = randomString(VerifierLength); err != nil {
			return errors.Wrapf(err, "failed to generate random verifier for PKCE authentication")
		}

		hash := sha256.New()

		if _, err = hash.Write([]byte(csrf.Verifier)); err != nil {
			return errors.Wrapf(err, "failed to hash PKCE verifier")
		}

		v.Set("code_challenge", base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash.Sum([]byte{})))
		v.Set("code_challenge_method", "S256")

		return nil
	})
}

func WithOpenbankingIntentID(intentID string, acr []string) AuthorizeOption {
	return authorizeHandler(func(c *Client, v url.Values, csrf *CSRF) error {
		var (
			acrClaimRequest = ClaimRequest{
				Essential: true,
			}
			signedToken             string
			requestObjectExpiration = time.Minute
			err                     error
		)

		if len(acr) == 1 {
			acrClaimRequest.Value = acr[0]
		} else {
			acrClaimRequest.Values = acr
		}

		if c.Config.RequestObjectExpiration != nil {
			requestObjectExpiration = *c.Config.RequestObjectExpiration
		}

		claims := jwt.MapClaims{
			"exp":   time.Now().Add(requestObjectExpiration).Unix(),
			"nonce": csrf.Nonce,
			"state": csrf.State,
			"claims": ClaimRequests{
				Userinfo: map[string]*ClaimRequest{
					"openbanking_intent_id": {
						Essential: true,
						Value:     intentID,
					},
				},
				IDToken: map[string]*ClaimRequest{
					"openbanking_intent_id": {
						Essential: true,
						Value:     intentID,
					},
					"acr": &acrClaimRequest,
				},
			},
		}

		if c.Config.RedirectURL != nil {
			claims["redirect_uri"] = c.Config.RedirectURL.String()
		}

		if len(c.Config.Scopes) > 0 {
			claims["scope"] = strings.Join(c.Config.Scopes, " ")
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

		if signedToken, err = token.SignedString(c.signingKey); err != nil {
			return errors.Wrapf(err, "failed to sign openbanking request object")
		}

		v.Set("request", signedToken)

		return nil
	})
}

func (c *Client) AuthorizeURL(options ...AuthorizeOption) (authorizeURL string, csrf CSRF, err error) {
	if csrf.State, err = randomString(StateLength); err != nil {
		return authorizeURL, csrf, err
	}

	if csrf.Nonce, err = randomString(NonceLength); err != nil {
		return authorizeURL, csrf, err
	}

	values := url.Values{
		"response_type": {"code"},
		"client_id":     {c.Config.ClientID},
		"nonce":         {csrf.Nonce},
		"state":         {csrf.State},
	}

	if c.Config.RedirectURL != nil {
		values.Set("redirect_uri", c.Config.RedirectURL.String())
	}

	if len(c.Config.Scopes) > 0 {
		values.Set("scope", strings.Join(c.Config.Scopes, " "))
	}

	for _, o := range options {
		if err = o.apply(c, values, &csrf); err != nil {
			return authorizeURL, csrf, err
		}
	}

	return fmt.Sprintf("%s?%s", c.Config.GetAuthorizeURL(), values.Encode()), csrf, nil
}

func (c *Client) Exchange(code string, state string, csrf CSRF) (token Token, err error) {
	var (
		response *http.Response
		body     []byte
	)

	values := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {c.Config.ClientID},
		"redirect_uri": {c.Config.RedirectURL.String()},
	}

	if csrf.Verifier != "" {
		values.Set("code_verifier", csrf.Verifier)
	}

	if response, err = c.c.PostForm(c.Config.GetTokenURL(), values); err != nil {
		return token, fmt.Errorf("failed to exchange token: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		if body, err = ioutil.ReadAll(response.Body); err != nil {
			return token, fmt.Errorf("failed to read exchange response body: %w", err)
		}

		return token, fmt.Errorf("failed to exchange token %d: %s", response.StatusCode, string(body))
	}

	if body, err = ioutil.ReadAll(response.Body); err != nil {
		return token, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &token); err != nil {
		return token, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	if state != csrf.State {
		return token, errors.New("invalid state")
	}

	// TODO check nonce

	return token, nil
}

func (c *Client) Userinfo(token string) (body map[string]interface{}, err error) {
	var (
		request  *http.Request
		response *http.Response
		bs       []byte
	)

	if request, err = http.NewRequest("GET", c.Config.GetUserinfoURL(), nil); err != nil {
		return body, fmt.Errorf("failed to build userinfo request: %w", err)
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	if response, err = c.c.Do(request); err != nil {
		return body, fmt.Errorf("failed to call userinfo endpoint: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		var errorBody []byte

		if errorBody, err = ioutil.ReadAll(response.Body); err != nil {
			return body, fmt.Errorf("failed to read userinfo response body: %w", err)
		}

		return body, fmt.Errorf("failed to get userinfo %d: %s", response.StatusCode, string(errorBody))
	}

	if bs, err = ioutil.ReadAll(response.Body); err != nil {
		return body, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	if err = json.Unmarshal(bs, &body); err != nil {
		return body, err
	}

	return body, nil
}

func (c *Client) IntrospectToken(token string) (*o2models.IntrospectResponse, error) {
	var (
		resp *o2Params.IntrospectOK
		err  error
	)

	if resp, err = c.Oauth2.Oauth2.Introspect(o2Params.NewIntrospectParams().
		WithToken(&token), nil); err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func randomString(length int) (string, error) {
	var (
		data = make([]byte, length)
		err  error
	)

	if _, err = io.ReadFull(rand.Reader, data); err != nil {
		return "", errors.Wrapf(err, "failed to generate random string")
	}

	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), nil
}
