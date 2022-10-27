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

// WellKnown WellKnown response
//
// WellKnown represents important OpenID Connect discovery metadata.
//
// It includes links to several endpoints (e.g. /oauth2/token) and exposes information on supported signature algorithms
// among others.
//
// swagger:model wellKnown
type WellKnown struct {

	// acr values supported
	AcrValuesSupported []string `json:"acr_values_supported"`

	// optional JSON array containing a list of the encryption algorithms (alg values) supported by the authorization endpoint to encrypt the response.
	AuthorizationEncryptionAlgValuesSupported []string `json:"authorization_encryption_alg_values_supported"`

	// optional JSON array containing a list of the encryption algorithms (enc values) supported by the authorization endpoint to encrypt the response.
	AuthorizationEncryptionEncValuesSupported []string `json:"authorization_encryption_enc_values_supported"`

	// URL of the OP's OAuth 2.0 Authorization Endpoint.
	// Example: https://example.com/oauth2/auth
	// Required: true
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// optional JSON array containing a list of the signing algorithms supported by the authorization endpoint to sign the response.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported"`

	// URL of the OP's Backchannel Authentication Endpoint
	BackchannelAuthenticationEndpoint string `json:"backchannel_authentication_endpoint,omitempty"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for signed authentication requests
	// If omitted, signed authentication requests are not supported by the OP.
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string `json:"backchannel_authentication_request_signing_alg_values_supported"`

	// Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP
	// session with the OP. If supported, the sid Claim is also included in ID Tokens issued by the OP
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// Boolean value specifying whether the OP supports back-channel logout, with true indicating support.
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`

	// JSON array containing one or more of the following values: poll, ping, and push.
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported"`

	// Boolean value specifying whether the OP supports the use of the user_code parameter, with true indicating support.
	// If omitted, the default value is false.
	BackchannelUserCodeParameterSupported bool `json:"backchannel_user_code_parameter_supported,omitempty"`

	// The URL of the CDR Arrangement Revocation End Point for consent revocation.
	// Available only for "cdr_australia" workspace profile.
	CdrArrangementRevocationEndpoint string `json:"cdr_arrangement_revocation_endpoint,omitempty"`

	// Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
	ClaimsParameterSupported bool `json:"claims_parameter_supported,omitempty"`

	// JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply
	// values for. Note that for privacy or other reasons, this might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported"`

	// List of supported Proof Key for Code Exchange (PKCE) code challenge methods
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	// URL of the authorization server's device authorization endpoint
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// Boolean value specifying whether the OP can pass iss (issuer) and sid (session ID) query parameters to identify
	// the RP session with the OP when the frontchannel_logout_uri is used. If supported, the sid Claim is also
	// included in ID Tokens issued by the OP.
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`

	// Boolean value specifying whether the OP supports HTTP-based logout, with true indicating support.
	FrontchannelLogoutSupported bool `json:"frontchannel_logout_supported,omitempty"`

	// JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT
	IDTokenEncryptionAlgValuesSupported []string `json:"id_token_encryption_alg_values_supported"`

	// JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT
	IDTokenEncryptionEncValuesSupported []string `json:"id_token_encryption_enc_values_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token
	// to encode the Claims in a JWT.
	// Required: true
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// OAuth 2.0 Introspection Endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// JSON array containing a list of Client Authentication methods supported by Introspection Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`

	// URL using the https scheme with no query or fragment component that the OP asserts as its IssuerURL Identifier.
	// If IssuerURL discovery is supported , this value MUST be identical to the issuer value returned
	// by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this IssuerURL.
	// Example: https://example.com/
	// Required: true
	Issuer string `json:"issuer"`

	// URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate
	// signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs
	// to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
	// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
	// NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of
	// keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
	// Example: https://example.com/.well-known/jwks.json
	// Required: true
	JwksURI string `json:"jwks_uri"`

	// mtls endpoint aliases
	MtlsEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`

	// mtls issuer
	MtlsIssuer string `json:"mtls_issuer,omitempty"`

	// The URL of the pushed authorization request endpoint at which a client can post an authorization request to exchange
	// for a "request_uri" value usable at the authorization server.
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

	// URL of the authorization server's OAuth 2.0 dynamic client registration endpoint.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// List of JWE encryption algorithms (alg values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by a value and when it is passed by a reference.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported"`

	// List of JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by a value and when it is passed by a reference.
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
	// These algorithms are used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
	// Servers SHOULD support none and RS256.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`

	// Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`

	// Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`

	// Boolean parameter indicating whether the authorization server accepts authorization request data only via PAR.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

	// Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
	// using the request_uris registration parameter.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`

	// JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
	ResponseModesSupported []string `json:"response_modes_supported"`

	// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID
	// Providers MUST support the code, id_token, and the token id_token Response Type values.
	// Required: true
	ResponseTypesSupported []string `json:"response_types_supported"`

	// URL of the authorization server's OAuth 2.0 revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// JSON array containing a list of Client Authentication methods supported by Revocation Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`

	// SON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST
	// support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used
	ScopesSupported []string `json:"scopes_supported"`

	// JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include
	// pairwise and public.
	// Example: public, pairwise
	// Required: true
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// Boolean value indicating server support for mutual TLS client certificate bound access tokens
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// URL of the OP's OAuth 2.0 Token Endpoint
	// Example: https://example.com/oauth2/token
	// Required: true
	TokenEndpoint string `json:"token_endpoint"`

	// JSON array containing a list of Client Authentication methods supported by Token Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// JSON array containing a list of the JWS signing algorithms ("alg" values) supported by the token endpoint for the
	// signature on the JWT [JWT] used to authenticate the client at the token endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	// This metadata entry MUST be present if either of these authentication methods are specified in the "token_endpoint_auth_methods_supported" entry.
	// No default algorithms are implied if this entry is omitted.  Servers SHOULD support "RS256".  The value "none" MUST NOT be used.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`

	// URL of the OP's UserInfo Endpoint.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported"`
}

// Validate validates this well known
func (m *WellKnown) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorizationEncryptionAlgValuesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthorizationEncryptionEncValuesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthorizationEndpoint(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGrantTypesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIDTokenEncryptionAlgValuesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIDTokenEncryptionEncValuesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIDTokenSigningAlgValuesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIntrospectionEndpointAuthMethodsSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJwksURI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMtlsEndpointAliases(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponseModesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponseTypesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRevocationEndpointAuthMethodsSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubjectTypesSupported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpoint(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpointAuthMethodsSupported(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var wellKnownAuthorizationEncryptionAlgValuesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["RSA-OAEP","RSA-OAEP-256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownAuthorizationEncryptionAlgValuesSupportedItemsEnum = append(wellKnownAuthorizationEncryptionAlgValuesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateAuthorizationEncryptionAlgValuesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownAuthorizationEncryptionAlgValuesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateAuthorizationEncryptionAlgValuesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthorizationEncryptionAlgValuesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.AuthorizationEncryptionAlgValuesSupported); i++ {

		// value enum
		if err := m.validateAuthorizationEncryptionAlgValuesSupportedItemsEnum("authorization_encryption_alg_values_supported"+"."+strconv.Itoa(i), "body", m.AuthorizationEncryptionAlgValuesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownAuthorizationEncryptionEncValuesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["A256GCM","A128CBC-HS256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownAuthorizationEncryptionEncValuesSupportedItemsEnum = append(wellKnownAuthorizationEncryptionEncValuesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateAuthorizationEncryptionEncValuesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownAuthorizationEncryptionEncValuesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateAuthorizationEncryptionEncValuesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthorizationEncryptionEncValuesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.AuthorizationEncryptionEncValuesSupported); i++ {

		// value enum
		if err := m.validateAuthorizationEncryptionEncValuesSupportedItemsEnum("authorization_encryption_enc_values_supported"+"."+strconv.Itoa(i), "body", m.AuthorizationEncryptionEncValuesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *WellKnown) validateAuthorizationEndpoint(formats strfmt.Registry) error {

	if err := validate.RequiredString("authorization_endpoint", "body", m.AuthorizationEndpoint); err != nil {
		return err
	}

	return nil
}

var wellKnownGrantTypesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authorization_code","implicit","client_credentials","refresh_token","password","urn:ietf:params:oauth:grant-type:jwt-bearer","urn:openid:params:grant-type:ciba","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownGrantTypesSupportedItemsEnum = append(wellKnownGrantTypesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateGrantTypesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownGrantTypesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateGrantTypesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantTypesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.GrantTypesSupported); i++ {

		// value enum
		if err := m.validateGrantTypesSupportedItemsEnum("grant_types_supported"+"."+strconv.Itoa(i), "body", m.GrantTypesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownIDTokenEncryptionAlgValuesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["RSA-OAEP","RSA-OAEP-256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownIDTokenEncryptionAlgValuesSupportedItemsEnum = append(wellKnownIDTokenEncryptionAlgValuesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateIDTokenEncryptionAlgValuesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownIDTokenEncryptionAlgValuesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateIDTokenEncryptionAlgValuesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.IDTokenEncryptionAlgValuesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.IDTokenEncryptionAlgValuesSupported); i++ {

		// value enum
		if err := m.validateIDTokenEncryptionAlgValuesSupportedItemsEnum("id_token_encryption_alg_values_supported"+"."+strconv.Itoa(i), "body", m.IDTokenEncryptionAlgValuesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownIDTokenEncryptionEncValuesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["A256GCM","A128CBC-HS256"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownIDTokenEncryptionEncValuesSupportedItemsEnum = append(wellKnownIDTokenEncryptionEncValuesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateIDTokenEncryptionEncValuesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownIDTokenEncryptionEncValuesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateIDTokenEncryptionEncValuesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.IDTokenEncryptionEncValuesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.IDTokenEncryptionEncValuesSupported); i++ {

		// value enum
		if err := m.validateIDTokenEncryptionEncValuesSupportedItemsEnum("id_token_encryption_enc_values_supported"+"."+strconv.Itoa(i), "body", m.IDTokenEncryptionEncValuesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *WellKnown) validateIDTokenSigningAlgValuesSupported(formats strfmt.Registry) error {

	if err := validate.Required("id_token_signing_alg_values_supported", "body", m.IDTokenSigningAlgValuesSupported); err != nil {
		return err
	}

	return nil
}

var wellKnownIntrospectionEndpointAuthMethodsSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownIntrospectionEndpointAuthMethodsSupportedItemsEnum = append(wellKnownIntrospectionEndpointAuthMethodsSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateIntrospectionEndpointAuthMethodsSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownIntrospectionEndpointAuthMethodsSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateIntrospectionEndpointAuthMethodsSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.IntrospectionEndpointAuthMethodsSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.IntrospectionEndpointAuthMethodsSupported); i++ {

		// value enum
		if err := m.validateIntrospectionEndpointAuthMethodsSupportedItemsEnum("introspection_endpoint_auth_methods_supported"+"."+strconv.Itoa(i), "body", m.IntrospectionEndpointAuthMethodsSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *WellKnown) validateIssuer(formats strfmt.Registry) error {

	if err := validate.RequiredString("issuer", "body", m.Issuer); err != nil {
		return err
	}

	return nil
}

func (m *WellKnown) validateJwksURI(formats strfmt.Registry) error {

	if err := validate.RequiredString("jwks_uri", "body", m.JwksURI); err != nil {
		return err
	}

	return nil
}

func (m *WellKnown) validateMtlsEndpointAliases(formats strfmt.Registry) error {
	if swag.IsZero(m.MtlsEndpointAliases) { // not required
		return nil
	}

	if m.MtlsEndpointAliases != nil {
		if err := m.MtlsEndpointAliases.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mtls_endpoint_aliases")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("mtls_endpoint_aliases")
			}
			return err
		}
	}

	return nil
}

var wellKnownResponseModesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownResponseModesSupportedItemsEnum = append(wellKnownResponseModesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateResponseModesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownResponseModesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateResponseModesSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.ResponseModesSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.ResponseModesSupported); i++ {

		// value enum
		if err := m.validateResponseModesSupportedItemsEnum("response_modes_supported"+"."+strconv.Itoa(i), "body", m.ResponseModesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownResponseTypesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["token","id_token","code","code id_token","token id_token","token code","token id_token code","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownResponseTypesSupportedItemsEnum = append(wellKnownResponseTypesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateResponseTypesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownResponseTypesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateResponseTypesSupported(formats strfmt.Registry) error {

	if err := validate.Required("response_types_supported", "body", m.ResponseTypesSupported); err != nil {
		return err
	}

	for i := 0; i < len(m.ResponseTypesSupported); i++ {

		// value enum
		if err := m.validateResponseTypesSupportedItemsEnum("response_types_supported"+"."+strconv.Itoa(i), "body", m.ResponseTypesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownRevocationEndpointAuthMethodsSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownRevocationEndpointAuthMethodsSupportedItemsEnum = append(wellKnownRevocationEndpointAuthMethodsSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateRevocationEndpointAuthMethodsSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownRevocationEndpointAuthMethodsSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateRevocationEndpointAuthMethodsSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.RevocationEndpointAuthMethodsSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.RevocationEndpointAuthMethodsSupported); i++ {

		// value enum
		if err := m.validateRevocationEndpointAuthMethodsSupportedItemsEnum("revocation_endpoint_auth_methods_supported"+"."+strconv.Itoa(i), "body", m.RevocationEndpointAuthMethodsSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

var wellKnownSubjectTypesSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["public","pairwise"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownSubjectTypesSupportedItemsEnum = append(wellKnownSubjectTypesSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateSubjectTypesSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownSubjectTypesSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateSubjectTypesSupported(formats strfmt.Registry) error {

	if err := validate.Required("subject_types_supported", "body", m.SubjectTypesSupported); err != nil {
		return err
	}

	for i := 0; i < len(m.SubjectTypesSupported); i++ {

		// value enum
		if err := m.validateSubjectTypesSupportedItemsEnum("subject_types_supported"+"."+strconv.Itoa(i), "body", m.SubjectTypesSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *WellKnown) validateTokenEndpoint(formats strfmt.Registry) error {

	if err := validate.RequiredString("token_endpoint", "body", m.TokenEndpoint); err != nil {
		return err
	}

	return nil
}

var wellKnownTokenEndpointAuthMethodsSupportedItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		wellKnownTokenEndpointAuthMethodsSupportedItemsEnum = append(wellKnownTokenEndpointAuthMethodsSupportedItemsEnum, v)
	}
}

func (m *WellKnown) validateTokenEndpointAuthMethodsSupportedItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, wellKnownTokenEndpointAuthMethodsSupportedItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *WellKnown) validateTokenEndpointAuthMethodsSupported(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthMethodsSupported) { // not required
		return nil
	}

	for i := 0; i < len(m.TokenEndpointAuthMethodsSupported); i++ {

		// value enum
		if err := m.validateTokenEndpointAuthMethodsSupportedItemsEnum("token_endpoint_auth_methods_supported"+"."+strconv.Itoa(i), "body", m.TokenEndpointAuthMethodsSupported[i]); err != nil {
			return err
		}

	}

	return nil
}

// ContextValidate validate this well known based on the context it is used
func (m *WellKnown) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMtlsEndpointAliases(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WellKnown) contextValidateMtlsEndpointAliases(ctx context.Context, formats strfmt.Registry) error {

	if m.MtlsEndpointAliases != nil {
		if err := m.MtlsEndpointAliases.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("mtls_endpoint_aliases")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("mtls_endpoint_aliases")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *WellKnown) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WellKnown) UnmarshalBinary(b []byte) error {
	var res WellKnown
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
