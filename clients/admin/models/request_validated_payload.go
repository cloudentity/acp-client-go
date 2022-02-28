// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// RequestValidatedPayload request validated payload
//
// swagger:model RequestValidatedPayload
type RequestValidatedPayload struct {

	// anonymous
	Anonymous bool `json:"anonymous,omitempty"`

	// api
	API *API `json:"api,omitempty"`

	// claims
	Claims JwtClaims `json:"claims,omitempty"`

	// OAuth client application identifier.
	ClientID string `json:"client_id,omitempty"`

	// Human readable name of a client application
	ClientName string `json:"client_name,omitempty"`

	// Stores information if the owner of the client application is a developer.
	CreatedByDeveloper bool `json:"created_by_developer,omitempty"`

	// gateway
	Gateway *Gateway `json:"gateway,omitempty"`

	// Stores the information which grant type was selected to perfom a given action.
	// Matches one of allowed OAuth client grant types for a given client.
	GrantType string `json:"grant_type,omitempty"`

	// invalid token
	InvalidToken bool `json:"invalid_token,omitempty"`

	// Stores information if the client application is a public one.
	Public bool `json:"public,omitempty"`

	// Requester IP address obtained from system network socket information.
	RemoteAddr string `json:"remote_addr,omitempty"`

	// result
	Result *PolicyValidationResult `json:"result,omitempty"`

	// ID of the authorization server (workspace) to which an access request is tied.
	ServerID string `json:"server_id,omitempty"`

	// service
	Service *Service `json:"service,omitempty"`

	// Session id of a given subject. It's uniform across the authentication processes.
	// It can be used as a correlation ID between a different audit events.
	SessionID string `json:"session_id,omitempty"`

	// Identification of the principal that is the subject of authorization.
	// For the authorization grant, the subject typically identifies an authorized accessor for which the access token is being requested.
	// For client authentication, the subject is the client_id of the OAuth client.
	Subject string `json:"subject,omitempty"`

	// Stores information if the client application is a system tenant's application.
	System bool `json:"system,omitempty"`

	// Token endpoint authentication method configured for a client application.
	// Enum: [client_secret_basic client_secret_post client_secret_jwt private_key_jwt self_signed_tls_client_auth tls_client_auth none]
	TokenEndpointAuthnMethod string `json:"token_endpoint_authn_method,omitempty"`

	// Token signature
	TokenSignature string `json:"token_signature,omitempty"`

	// A characteristic string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.
	UserAgent string `json:"user_agent,omitempty"`

	// ID of the authorization server (workspace) to which a resource is tied.
	WorkspaceID string `json:"workspace_id,omitempty"`

	// Requester IP address obtained from X-Forwarded-For header.
	XForwardedFor string `json:"x_forwarded_for,omitempty"`

	// Requester IP address obtained from X-Real-IP header.
	XRealIP string `json:"x_real_ip,omitempty"`
}

// Validate validates this request validated payload
func (m *RequestValidatedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAPI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClaims(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGateway(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResult(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
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

func (m *RequestValidatedPayload) validateAPI(formats strfmt.Registry) error {
	if swag.IsZero(m.API) { // not required
		return nil
	}

	if m.API != nil {
		if err := m.API.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("api")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("api")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) validateClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.Claims) { // not required
		return nil
	}

	if m.Claims != nil {
		if err := m.Claims.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("claims")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) validateGateway(formats strfmt.Registry) error {
	if swag.IsZero(m.Gateway) { // not required
		return nil
	}

	if m.Gateway != nil {
		if err := m.Gateway.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("gateway")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("gateway")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) validateResult(formats strfmt.Registry) error {
	if swag.IsZero(m.Result) { // not required
		return nil
	}

	if m.Result != nil {
		if err := m.Result.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) validateService(formats strfmt.Registry) error {
	if swag.IsZero(m.Service) { // not required
		return nil
	}

	if m.Service != nil {
		if err := m.Service.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

var requestValidatedPayloadTypeTokenEndpointAuthnMethodPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","self_signed_tls_client_auth","tls_client_auth","none"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		requestValidatedPayloadTypeTokenEndpointAuthnMethodPropEnum = append(requestValidatedPayloadTypeTokenEndpointAuthnMethodPropEnum, v)
	}
}

const (

	// RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretBasic captures enum value "client_secret_basic"
	RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretBasic string = "client_secret_basic"

	// RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretPost captures enum value "client_secret_post"
	RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretPost string = "client_secret_post"

	// RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretJwt captures enum value "client_secret_jwt"
	RequestValidatedPayloadTokenEndpointAuthnMethodClientSecretJwt string = "client_secret_jwt"

	// RequestValidatedPayloadTokenEndpointAuthnMethodPrivateKeyJwt captures enum value "private_key_jwt"
	RequestValidatedPayloadTokenEndpointAuthnMethodPrivateKeyJwt string = "private_key_jwt"

	// RequestValidatedPayloadTokenEndpointAuthnMethodSelfSignedTLSClientAuth captures enum value "self_signed_tls_client_auth"
	RequestValidatedPayloadTokenEndpointAuthnMethodSelfSignedTLSClientAuth string = "self_signed_tls_client_auth"

	// RequestValidatedPayloadTokenEndpointAuthnMethodTLSClientAuth captures enum value "tls_client_auth"
	RequestValidatedPayloadTokenEndpointAuthnMethodTLSClientAuth string = "tls_client_auth"

	// RequestValidatedPayloadTokenEndpointAuthnMethodNone captures enum value "none"
	RequestValidatedPayloadTokenEndpointAuthnMethodNone string = "none"
)

// prop value enum
func (m *RequestValidatedPayload) validateTokenEndpointAuthnMethodEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, requestValidatedPayloadTypeTokenEndpointAuthnMethodPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *RequestValidatedPayload) validateTokenEndpointAuthnMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.TokenEndpointAuthnMethod) { // not required
		return nil
	}

	// value enum
	if err := m.validateTokenEndpointAuthnMethodEnum("token_endpoint_authn_method", "body", m.TokenEndpointAuthnMethod); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this request validated payload based on the context it is used
func (m *RequestValidatedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAPI(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGateway(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateResult(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateService(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestValidatedPayload) contextValidateAPI(ctx context.Context, formats strfmt.Registry) error {

	if m.API != nil {
		if err := m.API.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("api")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("api")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) contextValidateClaims(ctx context.Context, formats strfmt.Registry) error {

	if err := m.Claims.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("claims")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("claims")
		}
		return err
	}

	return nil
}

func (m *RequestValidatedPayload) contextValidateGateway(ctx context.Context, formats strfmt.Registry) error {

	if m.Gateway != nil {
		if err := m.Gateway.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("gateway")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("gateway")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) contextValidateResult(ctx context.Context, formats strfmt.Registry) error {

	if m.Result != nil {
		if err := m.Result.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) contextValidateService(ctx context.Context, formats strfmt.Registry) error {

	if m.Service != nil {
		if err := m.Service.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestValidatedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestValidatedPayload) UnmarshalBinary(b []byte) error {
	var res RequestValidatedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
