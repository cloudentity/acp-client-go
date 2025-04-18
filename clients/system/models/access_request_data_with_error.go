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

// AccessRequestDataWithError access request data with error
//
// swagger:model AccessRequestDataWithError
type AccessRequestDataWithError struct {

	// Actor claims
	ActorClaims map[string]interface{} `json:"actor_claims,omitempty" yaml:"actor_claims,omitempty"`

	// ID of the User in Identity Pool that is affected by an action
	AffectedUserID string `json:"affected_user_id,omitempty" yaml:"affected_user_id,omitempty"`

	// ID of the Identity Pool of the User that is affected by an action
	AffectedUserPoolID string `json:"affected_user_pool_id,omitempty" yaml:"affected_user_pool_id,omitempty"`

	// The authentication mechanisms a user used to login.
	AuthenticationMechanisms []string `json:"authentication_mechanisms" yaml:"authentication_mechanisms"`

	// The visitor's city
	City string `json:"city,omitempty" yaml:"city,omitempty"`

	// OAuth client application identifier.
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// Human readable name of a client application
	ClientName string `json:"client_name,omitempty" yaml:"client_name,omitempty"`

	// The visitor's country
	CountryCode string `json:"country_code,omitempty" yaml:"country_code,omitempty"`

	// Stores information if the owner of the client application is a developer.
	CreatedByDeveloper bool `json:"created_by_developer,omitempty" yaml:"created_by_developer,omitempty"`

	// Arculix DBFP `jwt` cookie.
	Dbfp string `json:"dbfp,omitempty" yaml:"dbfp,omitempty"`

	// High level error name (request_forbidden, access_denied, invalid_request).
	Error string `json:"error,omitempty" yaml:"error,omitempty"`

	// Error root cause (invalid_pkce, invalid_state, user_policy_failed).
	ErrorCause string `json:"error_cause,omitempty" yaml:"error_cause,omitempty"`

	// Human readable error description
	ErrorDescription string `json:"error_description,omitempty" yaml:"error_description,omitempty"`

	// Error hint
	ErrorHint string `json:"error_hint,omitempty" yaml:"error_hint,omitempty"`

	// External error
	ExternalError bool `json:"external_error,omitempty" yaml:"external_error,omitempty"`

	// Stores the information which grant type was selected to perfom a given action.
	// Matches one of allowed OAuth client grant types for a given client.
	GrantType string `json:"grant_type,omitempty" yaml:"grant_type,omitempty"`

	// ID of the Group in Identity Pool
	GroupID string `json:"group_id,omitempty" yaml:"group_id,omitempty"`

	// ID of the Identity Pool
	IdentityPoolID string `json:"identity_pool_id,omitempty" yaml:"identity_pool_id,omitempty"`

	// IDP identifier
	IdpID string `json:"idp_id,omitempty" yaml:"idp_id,omitempty"`

	// IDP method
	IdpMethod string `json:"idp_method,omitempty" yaml:"idp_method,omitempty"`

	// Subject within the Identity Provider
	IdpSubject string `json:"idp_subject,omitempty" yaml:"idp_subject,omitempty"`

	// The visitor's latitude
	Latitude string `json:"latitude,omitempty" yaml:"latitude,omitempty"`

	// The visitor's longitude
	Longitude string `json:"longitude,omitempty" yaml:"longitude,omitempty"`

	// May act claims
	MayActClaims map[string]interface{} `json:"may_act_claims,omitempty" yaml:"may_act_claims,omitempty"`

	// ID of the Organization
	OrganizationID string `json:"organization_id,omitempty" yaml:"organization_id,omitempty"`

	// Stores information if the client application is a public one.
	Public bool `json:"public,omitempty" yaml:"public,omitempty"`

	// True if user had to do login recovery during authentication
	Recovery bool `json:"recovery,omitempty" yaml:"recovery,omitempty"`

	// Requester IP address obtained from system network socket information.
	RemoteAddr string `json:"remote_addr,omitempty" yaml:"remote_addr,omitempty"`

	// risk engine context
	RiskEngineContext *RiskContext `json:"risk_engine_context,omitempty" yaml:"risk_engine_context,omitempty"`

	// ID of the authorization server (workspace) to which an access request is tied.
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// Session id of a given subject. It's uniform across the authentication processes.
	// It can be used as a correlation ID between a different audit events.
	SessionID string `json:"session_id,omitempty" yaml:"session_id,omitempty"`

	// Identification of the principal that is the subject of authorization.
	// For the authorization grant, the subject typically identifies an authorized accessor for which the access token is being requested.
	// For client authentication, the subject is the client_id of the OAuth client.
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`

	// Stores information if the client application is a system tenant's application.
	System bool `json:"system,omitempty" yaml:"system,omitempty"`

	// Token endpoint authentication method configured for a client application.
	// Enum: ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none","unspecified"]
	TokenEndpointAuthnMethod string `json:"token_endpoint_authn_method,omitempty" yaml:"token_endpoint_authn_method,omitempty"`

	// Token signature
	TokenSignature string `json:"token_signature,omitempty" yaml:"token_signature,omitempty"`

	// Requester IP address obtained from True-Client-IP header.
	TrueClientIP string `json:"true_client_ip,omitempty" yaml:"true_client_ip,omitempty"`

	// A characteristic string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`

	// ID of the User in Identity Pool
	UserID string `json:"user_id,omitempty" yaml:"user_id,omitempty"`

	// ID of the Identity Pool
	UserPoolID string `json:"user_pool_id,omitempty" yaml:"user_pool_id,omitempty"`

	// ID of the authorization server (workspace) to which a resource is tied.
	WorkspaceID string `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`

	// Requester IP address obtained from X-Forwarded-For header.
	XForwardedFor string `json:"x_forwarded_for,omitempty" yaml:"x_forwarded_for,omitempty"`

	// Requester IP address obtained from X-Real-IP header.
	XRealIP string `json:"x_real_ip,omitempty" yaml:"x_real_ip,omitempty"`
}

// Validate validates this access request data with error
func (m *AccessRequestDataWithError) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationMechanisms(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRiskEngineContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTokenEndpointAuthnMethod(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var accessRequestDataWithErrorAuthenticationMechanismsItemsEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["totp","password","otp","email_otp","sms_otp","webauthn"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		accessRequestDataWithErrorAuthenticationMechanismsItemsEnum = append(accessRequestDataWithErrorAuthenticationMechanismsItemsEnum, v)
	}
}

func (m *AccessRequestDataWithError) validateAuthenticationMechanismsItemsEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, accessRequestDataWithErrorAuthenticationMechanismsItemsEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AccessRequestDataWithError) validateAuthenticationMechanisms(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationMechanisms) { // not required
		return nil
	}

	for i := 0; i < len(m.AuthenticationMechanisms); i++ {

		// value enum
		if err := m.validateAuthenticationMechanismsItemsEnum("authentication_mechanisms"+"."+strconv.Itoa(i), "body", m.AuthenticationMechanisms[i]); err != nil {
			return err
		}

	}

	return nil
}

func (m *AccessRequestDataWithError) validateRiskEngineContext(formats strfmt.Registry) error {
	if swag.IsZero(m.RiskEngineContext) { // not required
		return nil
	}

	if m.RiskEngineContext != nil {
		if err := m.RiskEngineContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("risk_engine_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("risk_engine_context")
			}
			return err
		}
	}

	return nil
}

var accessRequestDataWithErrorTypeTokenEndpointAuthnMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none","unspecified"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		accessRequestDataWithErrorTypeTokenEndpointAuthnMethodPropEnum = append(accessRequestDataWithErrorTypeTokenEndpointAuthnMethodPropEnum, v)
	}
}

const (

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretBasic captures enum value "client_secret_basic"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretBasic string = "client_secret_basic"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretPost captures enum value "client_secret_post"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretPost string = "client_secret_post"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretJwt captures enum value "client_secret_jwt"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodClientSecretJwt string = "client_secret_jwt"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodPrivateKeyJwt captures enum value "private_key_jwt"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodPrivateKeyJwt string = "private_key_jwt"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodSelfSignedTLSClientAuth captures enum value "self_signed_tls_client_auth"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodSelfSignedTLSClientAuth string = "self_signed_tls_client_auth"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodTLSClientAuth captures enum value "tls_client_auth"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodTLSClientAuth string = "tls_client_auth"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodNone captures enum value "none"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodNone string = "none"

	// AccessRequestDataWithErrorTokenEndpointAuthnMethodUnspecified captures enum value "unspecified"
	AccessRequestDataWithErrorTokenEndpointAuthnMethodUnspecified string = "unspecified"
)

// prop value enum
func (m *AccessRequestDataWithError) validateTokenEndpointAuthnMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, accessRequestDataWithErrorTypeTokenEndpointAuthnMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AccessRequestDataWithError) validateTokenEndpointAuthnMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthnMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateTokenEndpointAuthnMethodEnum("token_endpoint_authn_method", "body", m.TokenEndpointAuthnMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this access request data with error based on the context it is used
func (m *AccessRequestDataWithError) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRiskEngineContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccessRequestDataWithError) contextValidateRiskEngineContext(ctx context.Context, formats strfmt.Registry) error {

	if m.RiskEngineContext != nil {

		if swag.IsZero(m.RiskEngineContext) { // not required
			return nil
		}

		if err := m.RiskEngineContext.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("risk_engine_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("risk_engine_context")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccessRequestDataWithError) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccessRequestDataWithError) UnmarshalBinary(b []byte) error {
	var res AccessRequestDataWithError
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
