// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OpenbankingUKDynamicClientRegistrationResponse openbanking u k dynamic client registration response
//
// swagger:model OpenbankingUKDynamicClientRegistrationResponse
type OpenbankingUKDynamicClientRegistrationResponse struct {

	// Kind of the application. The default, if omitted, is web. The defined values are native or web.
	// Example: web
	ApplicationType string `json:"application_type,omitempty"`

	// oauth client allowed audience
	Audience []string `json:"audience"`

	// Boolean value indicating server support for mutual TLS client certificate-bound access tokens. If omitted, the default value is "false".
	CertificateBoundAccessToken bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// Time at which the client identifier was issued. The time is represented as the number of seconds from
	// 1970-01-01T00:00:00Z as measured in UTC until the date/time of issuance
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`

	// SecretExpiresAt is an integer holding the time at which the client secret will expire or 0 if it will not expire.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`

	// client URI
	ClientURI string `json:"client_uri,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// dynamically registered
	DynamicallyRegistered bool `json:"dynamically_registered,omitempty"`

	// oauth client grant types, allowed values: password, refresh_token, client_credentials, implicit, authorization_code
	// Example: ["password","refresh_token","client_credentials","implicit","authorization_code"]
	GrantTypes []string `json:"grant_types"`

	// oauth client id
	ID string `json:"client_id,omitempty"`

	// Algorithm for signing the ID Token issued to this Client.
	// The default value depends on authorization server configuration.
	// Example: ES256
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`

	// URL of JSON Web Key Set containing the public keys used by the client to authenticate
	JSONWebKeysURI string `json:"jwks_uri,omitempty"`

	// logo URI
	LogoURI string `json:"logo_uri,omitempty"`

	// human redable name
	// Example: My app
	Name string `json:"client_name,omitempty"`

	// policy url to read about how the profile data will be used
	PolicyURI string `json:"policy_uri,omitempty"`

	// oauth allowed redirect URIs
	// Example: ["https://example.com/callback"]
	RedirectURIs []string `json:"redirect_uris"`

	// Signing algorithm for a request object
	// Example: none
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`

	// Array of absolute URIs that points to the Request Object that holds authorization request parameters
	RequestURIs []string `json:"request_uris"`

	// oauth client response types, allowed values: token, id_token, code
	// Example: ["token","id_token","code"]
	ResponseTypes []string `json:"response_types"`

	// A string containing the value of an expected dNSName SAN entry in the certificate
	SanDNS string `json:"tls_client_auth_san_dns,omitempty"`

	// A string containing the value of an expected rfc822Name SAN entry in the certificate
	SanEmail string `json:"tls_client_auth_san_email,omitempty"`

	// A string representation of an IP address in either dotted decimal notation (for IPv4) or colon-delimited hexadecimal (for IPv6, as defined in [RFC5952]) that is expected to be present as an iPAddress SAN entry in the certificate
	SanIP string `json:"tls_client_auth_san_ip,omitempty"`

	// A string containing the value of an expected uniformResourceIdentifier SAN entry in the certificate
	SanURI string `json:"tls_client_auth_san_uri,omitempty"`

	// Optional comma separated scopes for compatibility with spec
	// Example: email offline_access openid
	Scope string `json:"scope,omitempty"`

	// oauth client scopes
	// Example: ["email","offline_access","openid"]
	Scopes []string `json:"scopes"`

	// URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a
	// file with a single JSON array of redirect_uri values.
	// Example: https://api.jsonbin.io/b/5db6ef08688fed59d2841f1e
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// A unique identifier string (e.g., a Universally Unique Identifier
	// (UUID)) assigned by the client developer or software publisher
	// The "software_id" SHOULD remain the same across
	// multiple updates or versions of the same piece of software.  The
	// value of this field is not intended to be human readable and is
	// usually opaque to the client and authorization server.
	SoftwareID string `json:"software_id,omitempty"`

	// software statement
	SoftwareStatement string `json:"software_statement,omitempty"`

	// A version identifier string for the client software identified by
	// "software_id".  The value of the "software_version" SHOULD change
	// on any update to the client software identified by the same
	// "software_id".
	SoftwareVersion string `json:"software_version,omitempty"`

	// An [RFC4514] string representation of the expected subject distinguished name of the certificate
	SubjectDN string `json:"tls_client_auth_subject_dn,omitempty"`

	// Subject identifier type
	SubjectType string `json:"subject_type,omitempty"`

	// Signing algorithm for a token endpoint
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// Token endpoint authentication method
	// Example: client_secret_basic
	TokenEndpointAuthnMethod string `json:"token_endpoint_auth_method,omitempty"`

	// terms of service url
	TosURI string `json:"tos_uri,omitempty"`

	// JWS alg algorithm REQUIRED for signing UserInfo Responses. If this is specified, the response will be JWT
	// [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the Claims
	// as a UTF-8 encoded JSON object using the application/json content-type.
	// Example: none
	UserinfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`

	// jwks
	Jwks *JWKs `json:"jwks,omitempty"`

	// privacy
	Privacy *ClientPrivacy `json:"privacy,omitempty"`
}

// Validate validates this openbanking u k dynamic client registration response
func (m *OpenbankingUKDynamicClientRegistrationResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivacy(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingUKDynamicClientRegistrationResponse) validateJwks(formats strfmt.Registry) error {
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

func (m *OpenbankingUKDynamicClientRegistrationResponse) validatePrivacy(formats strfmt.Registry) error {
	if swag.IsZero(m.Privacy) { // not required
		return nil
	}

	if m.Privacy != nil {
		if err := m.Privacy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("privacy")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking u k dynamic client registration response based on the context it is used
func (m *OpenbankingUKDynamicClientRegistrationResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePrivacy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingUKDynamicClientRegistrationResponse) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

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

func (m *OpenbankingUKDynamicClientRegistrationResponse) contextValidatePrivacy(ctx context.Context, formats strfmt.Registry) error {

	if m.Privacy != nil {
		if err := m.Privacy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("privacy")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingUKDynamicClientRegistrationResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingUKDynamicClientRegistrationResponse) UnmarshalBinary(b []byte) error {
	var res OpenbankingUKDynamicClientRegistrationResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}