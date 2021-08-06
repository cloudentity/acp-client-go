// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Server Multi Tenant authorization server
//
// swagger:model Server
type Server struct {

	// Access token strategy
	//
	// You can choose to go either with `JWT` or `opaque` tokens.
	//
	// The content of JSON Web Tokens is readable and it is possible to be decoded by anyone that
	// has a secret or a public key in their possession.
	//
	// Opaque tokens are in a proprietary form that contains an identifier to information stored on
	// the athorization server. To validate an opaque token, the recipient must call the server that
	// issued the token.
	// Example: jwt
	AccessTokenStrategy string `json:"access_token_strategy,omitempty"`

	// Access token time to live
	//
	// After an access token reaches its time to live, it expires and it cannot be used to
	// authenticate the client application.
	// Example: 1h10m30s
	// Format: duration
	AccessTokenTTL strfmt.Duration `json:"access_token_ttl,omitempty"`

	// Authorization code time to live
	//
	// After an authorization code reaches its time to live, it expires and it cannot be used to
	// authorize the request to the `/token` endpoint.
	// Example: 10m0s
	// Format: duration
	AuthorizationCodeTTL strfmt.Duration `json:"authorization_code_ttl,omitempty"`

	// backchannel token delivery modes supported
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported"`

	// backchannel user code parameter supported
	BackchannelUserCodeParameterSupported bool `json:"backchannel_user_code_parameter_supported,omitempty"`

	// Client certificate header name that contains the client certificate in the urlencoded Privacy-Enhanced
	// Mail (PEM) file format.
	ClientCertificateHeader string `json:"client_certificate_header,omitempty"`

	// Your server's label color in a HEX format.
	// Example: #007FFF
	Color string `json:"color,omitempty"`

	// Cookie max age
	//
	// Defines how long a cookie can live until it expires.
	// Example: 1h10m30s
	// Format: duration
	CookieMaxAge strfmt.Duration `json:"cookie_max_age,omitempty"`

	// dynamic client registration
	DynamicClientRegistration *DynamicClientRegistrationSettings `json:"dynamic_client_registration,omitempty"`

	// You can use this property to define a separator that is used for dynamic scopes.
	//
	// For example, the default separator is `.`, so the scope could look like the following:
	// `users.*`.
	//
	// For Open Banking Brazil compliant servers, the `:` separator should be used.
	DynamicScopeSeparator string `json:"dynamic_scope_separator,omitempty"`

	// If enabled, IDP discovery automatically redirects the user to their own IDP and does not
	// display IDPs of other users while the users accesses the server/application.
	// Example: false
	EnableIdpDiscovery bool `json:"enable_idp_discovery,omitempty"`

	// If enabled, it is possible to manually register clients withouth the use of software
	// statements.
	//
	// This flag is enabled, when the `enable_trust_anchor` flag is set to `false`. You can disable
	// it using API, but it cannot be manually enabled.
	EnableLegacyClientsWithNoSoftwareStatement bool `json:"enable_legacy_clients_with_no_software_statement,omitempty"`

	// If enabled, the server is visible on the Quick Access tab on the login page.
	EnableQuickAccess bool `json:"enable_quick_access,omitempty"`

	// If enabled, it makes it obligatory to provide a software statement signed by a trusted certificate authority
	// when registering a client application with the use of the Dynamic Client Registration (DCR).
	//
	// In public key infrastructure (PKI), trust anchors are certification authorities. They are
	// represented by a certificate that is used to verify the signature of a certificate issued by
	// a particular trust anchor.
	EnableTrustAnchor bool `json:"enable_trust_anchor,omitempty"`

	// Define whether you want to enforce using the Proof Key of Code Exchange (PKCE) for both
	// private and public clients.
	//
	// PKCE is an OAuth security extension that prevents malicious applications or codes that
	// intercepted authorization code from exchanging it for an access token.
	// Example: false
	EnforcePkce bool `json:"enforce_pkce,omitempty"`

	// Define whether you want to enforce using the Proof Key of Code Exchange (PKCE) for
	// public clients.
	//
	// Public clients, like mobile applications or JavaScript-based applications, by their design,
	// cannot store client secrets securely. For such clients, even encrypting the client secret
	// inside the application’s code is not a reliable way of protecting secrets as the application
	// can be decompiled and the client secret can be extracted while it is decrypted in the memory
	// of the application.
	//
	// For those reasons, ACP supports the use of PKCE as an addition to the authorization code
	// grant flow to provide a secure alternative to the implicit grant flow.
	// Example: false
	EnforcePkceForPublicClients bool `json:"enforce_pkce_for_public_clients,omitempty"`

	// An array that defines which of the OAuth 2.0 grant types are enabled for the authorization server.
	// Example: ["authorization_code","implicit","refresh_token","client_credentials"]
	GrantTypes []string `json:"grant_types"`

	// Unique identifier of an authorization server (workspace)
	//
	// If not provided, a random ID is generated.
	// Example: 935ab21c-b20a-11e9-a2a3-2a2ae2dbcce4
	ID string `json:"id,omitempty"`

	// ID token time to live
	//
	// After an ID token reaches its time to live, it expires and it cannot be used to provide
	// user profile information to a client application.
	// Example: 1h10m30s
	// Format: duration
	IDTokenTTL strfmt.Duration `json:"id_token_ttl,omitempty"`

	// Defines a custom issuer URL that can be used as the value of the `iss` claim in an access
	// token.
	//
	// If not provided, it is built dynamically based on the server's URL.
	// Example: http://example.com/default/default
	IssuerURL string `json:"issuer_url,omitempty"`

	// jwks
	Jwks *ServerJWKs `json:"jwks,omitempty"`

	// Determines which type of asymmetric algorithms (RSA or ECDSA) is used to generate keys for signing access and
	// ID tokens.
	//
	// It is used only as an input parameter for the Create Authorization Server API.
	// Example: rsa
	KeyType string `json:"key_type,omitempty"`

	// Logo URI
	LogoURI string `json:"logo_uri,omitempty"`

	// Display name of your authorization server
	// Example: Sample authorization server
	Name string `json:"name,omitempty"`

	// The profile of a server
	//
	// ACP is delivered with preconfigured workspace templates that enable quick and easy setup for
	// specific configuration patterns. For example, you can instantly create an Open Banking
	// compliant workspace that has all of the required mechanisms and settings already in place.
	// Example: default
	Profile string `json:"profile,omitempty"`

	// A flag that defines whether the client certificates should be read from request header's.
	//
	// In a situation that there are multiple ACP nodes running, a gateway, proxy, ingress, or a
	// load-balancer is needed. In this case, the client certificate cannot be read from the the
	// HTTP request body as, for example, with the use of the load-balancer, it would read the
	// load-balancer's certificate instead of the client's certificate. The solution to this issue
	// is to enable this flag and read the certificates from the request header.
	//
	// If set to `true`, the client certificate header is required to be present in request header's.
	ReadClientCertificateFromHeader bool `json:"read_client_certificate_from_header,omitempty"`

	// Refresh token time to live
	//
	// After a refresh token reaches its time to live, it expires and it cannot be used to obtain
	// new access tokens for a client application.
	// Example: 720h0m0s
	// Format: duration
	RefreshTokenTTL strfmt.Duration `json:"refresh_token_ttl,omitempty"`

	// You can provide root Certificate Authority (CA) certificates encoded to the Privacy-Enhanced
	// Mail (PEM) file format which are used for the `tls_client_auth` and the
	// `self_signed_tls_client_auth` client authentication methods that use the Mutual
	// Transport Layer Security (mTLS).
	//
	// If not set, the system root CA certifiates are used instead.
	RootCas string `json:"root_cas,omitempty"`

	// An array of rotated secrets that are still used to validate tokens
	// Example: ["jFpwIvuKJP46J71WqszPv1SrzoUr-cSILP9EPdlClB4"]
	RotatedSecrets []string `json:"rotated_secrets"`

	// Secret used for hashing
	//
	// It must have at least 32 characters. If not provided, it is generated.
	// Example: hW5WhKX_7w7BLwUQ6mn7Cp70_OoKI_F1y1hLS5U8lIU
	Secret string `json:"secret,omitempty"`

	// Salt used to hash `subject` when the `pairwise` subject type is used.
	//
	// Salt is a random data which is used as an additional input to one-way functions that hashes
	// data, passwords, and, in this case, subjects.
	//
	// It is recommended that your salt value is long for security reasons. Preferably, the salt
	// value should be at least the same length as the output of the hash.
	SubjectIdentifierAlgorithmSalt string `json:"subject_identifier_algorithm_salt,omitempty"`

	// An array that defines supported subject identifier types.
	//
	// Subject identifiers are locally unique and never reassigned identifiers within the Issuer
	// for the end-user and are inteded to be consumed by client applications. There are two types
	// of subject identifiers: `public` and `pairwise`.
	//
	// `public` identifiers provide the same `sub` claim value to all client applications.
	// `pairwise` identifiers provide different `sub` claim values to each client application. With
	// this approach, it makes it impossible for client applications to correlate the end-user's
	// activity without their permission.
	// Example: ["public","pairwise"]
	SubjectIdentifierTypes []string `json:"subject_identifier_types"`

	// tenant id
	TenantID string `json:"tenant_id,omitempty"`

	// An array that lists all of the supported token endpoint authentication methods for the
	// authorization server.
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods"`

	// token endpoint authn methods
	TokenEndpointAuthnMethods []string `json:"token_endpoint_authn_methods"`

	// trust anchor configuration
	TrustAnchorConfiguration *TrustAnchorConfiguration `json:"trust_anchor_configuration,omitempty"`

	// Server type
	//
	// It is an internal property used to recognize if the server is created for an admin portal,
	// a developer portal, or if it is a system or a regular workspace.
	// Example: regular
	Type string `json:"type,omitempty"`
}

// Validate validates this server
func (m *Server) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthorizationCodeTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCookieMaxAge(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDynamicClientRegistration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGrantTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIDTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRefreshTokenTTL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjectIdentifierTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpointAuthMethods(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpointAuthnMethods(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTrustAnchorConfiguration(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Server) validateAccessTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.AccessTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("access_token_ttl", "body", "duration", m.AccessTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Server) validateAuthorizationCodeTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthorizationCodeTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("authorization_code_ttl", "body", "duration", m.AuthorizationCodeTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Server) validateCookieMaxAge(formats strfmt.Registry) error {
	if swag.IsZero(m.CookieMaxAge) { // not required
		return nil
	}

	if err := validate.FormatOf("cookie_max_age", "body", "duration", m.CookieMaxAge.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Server) validateDynamicClientRegistration(formats strfmt.Registry) error {
	if swag.IsZero(m.DynamicClientRegistration) { // not required
		return nil
	}

	if m.DynamicClientRegistration != nil {
		if err := m.DynamicClientRegistration.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("dynamic_client_registration")
			}
			return err
		}
	}

	return nil
}

var serverGrantTypesItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authorization_code","implicit","client_credentials","refresh_token","password","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:openid:params:grant-type:ciba"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		serverGrantTypesItemsEnum = append(serverGrantTypesItemsEnum, v)
	}
}

func (m *Server) validateGrantTypesItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, serverGrantTypesItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Server) validateGrantTypes(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantTypes) { // not required
		return nil
	}

	for i := 0; i < len(m.GrantTypes); i++ {

		// value enum
		if err := m.validateGrantTypesItemsEnum("grant_types"+"."+strconv.Itoa(i), "body", m.GrantTypes[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *Server) validateIDTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.IDTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("id_token_ttl", "body", "duration", m.IDTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Server) validateJwks(formats strfmt.Registry) error {
	if swag.IsZero(m.Jwks) { // not required
		return nil
	}

	if m.Jwks != nil {
		if err := m.Jwks.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *Server) validateRefreshTokenTTL(formats strfmt.Registry) error {
	if swag.IsZero(m.RefreshTokenTTL) { // not required
		return nil
	}

	if err := validate.FormatOf("refresh_token_ttl", "body", "duration", m.RefreshTokenTTL.String(), formats); err != nil {
		return err
	}

	return nil
}

var serverSubjectIdentifierTypesItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["public","pairwise"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		serverSubjectIdentifierTypesItemsEnum = append(serverSubjectIdentifierTypesItemsEnum, v)
	}
}

func (m *Server) validateSubjectIdentifierTypesItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, serverSubjectIdentifierTypesItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Server) validateSubjectIdentifierTypes(formats strfmt.Registry) error {
	if swag.IsZero(m.SubjectIdentifierTypes) { // not required
		return nil
	}

	for i := 0; i < len(m.SubjectIdentifierTypes); i++ {

		// value enum
		if err := m.validateSubjectIdentifierTypesItemsEnum("subject_identifier_types"+"."+strconv.Itoa(i), "body", m.SubjectIdentifierTypes[i]); err != nil {
			return err
		}

	}

	return nil
}

var serverTokenEndpointAuthMethodsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		serverTokenEndpointAuthMethodsItemsEnum = append(serverTokenEndpointAuthMethodsItemsEnum, v)
	}
}

func (m *Server) validateTokenEndpointAuthMethodsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, serverTokenEndpointAuthMethodsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Server) validateTokenEndpointAuthMethods(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthMethods) { // not required
		return nil
	}

	for i := 0; i < len(m.TokenEndpointAuthMethods); i++ {

		// value enum
		if err := m.validateTokenEndpointAuthMethodsItemsEnum("token_endpoint_auth_methods"+"."+strconv.Itoa(i), "body", m.TokenEndpointAuthMethods[i]); err != nil {
			return err
		}

	}

	return nil
}

var serverTokenEndpointAuthnMethodsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		serverTokenEndpointAuthnMethodsItemsEnum = append(serverTokenEndpointAuthnMethodsItemsEnum, v)
	}
}

func (m *Server) validateTokenEndpointAuthnMethodsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, serverTokenEndpointAuthnMethodsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *Server) validateTokenEndpointAuthnMethods(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthnMethods) { // not required
		return nil
	}

	for i := 0; i < len(m.TokenEndpointAuthnMethods); i++ {

		// value enum
		if err := m.validateTokenEndpointAuthnMethodsItemsEnum("token_endpoint_authn_methods"+"."+strconv.Itoa(i), "body", m.TokenEndpointAuthnMethods[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *Server) validateTrustAnchorConfiguration(formats strfmt.Registry) error {
	if swag.IsZero(m.TrustAnchorConfiguration) { // not required
		return nil
	}

	if m.TrustAnchorConfiguration != nil {
		if err := m.TrustAnchorConfiguration.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("trust_anchor_configuration")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this server based on the context it is used
func (m *Server) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDynamicClientRegistration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTrustAnchorConfiguration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Server) contextValidateDynamicClientRegistration(ctx context.Context, formats strfmt.Registry) error {

	if m.DynamicClientRegistration != nil {
		if err := m.DynamicClientRegistration.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("dynamic_client_registration")
			}
			return err
		}
	}

	return nil
}

func (m *Server) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

	if m.Jwks != nil {
		if err := m.Jwks.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

func (m *Server) contextValidateTrustAnchorConfiguration(ctx context.Context, formats strfmt.Registry) error {

	if m.TrustAnchorConfiguration != nil {
		if err := m.TrustAnchorConfiguration.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("trust_anchor_configuration")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Server) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Server) UnmarshalBinary(b []byte) error {
	var res Server
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
