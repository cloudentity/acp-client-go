// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DCRRejectedEventPayload d c r rejected event payload
//
// swagger:model DCRRejectedEventPayload
type DCRRejectedEventPayload struct {

	// The visitor's city
	City string `json:"city,omitempty" yaml:"city,omitempty"`

	// The visitor's country
	CountryCode string `json:"country_code,omitempty" yaml:"country_code,omitempty"`

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

	// The visitor's latitude
	Latitude string `json:"latitude,omitempty" yaml:"latitude,omitempty"`

	// The visitor's longitude
	Longitude string `json:"longitude,omitempty" yaml:"longitude,omitempty"`

	// Requester IP address obtained from system network socket information.
	RemoteAddr string `json:"remote_addr,omitempty" yaml:"remote_addr,omitempty"`

	// Requester IP address obtained from True-Client-IP header.
	TrueClientIP string `json:"true_client_ip,omitempty" yaml:"true_client_ip,omitempty"`

	// A characteristic string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.
	UserAgent string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`

	// Requester IP address obtained from X-Forwarded-For header.
	XForwardedFor string `json:"x_forwarded_for,omitempty" yaml:"x_forwarded_for,omitempty"`

	// Requester IP address obtained from X-Real-IP header.
	XRealIP string `json:"x_real_ip,omitempty" yaml:"x_real_ip,omitempty"`
}

// Validate validates this d c r rejected event payload
func (m *DCRRejectedEventPayload) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this d c r rejected event payload based on context it is used
func (m *DCRRejectedEventPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DCRRejectedEventPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DCRRejectedEventPayload) UnmarshalBinary(b []byte) error {
	var res DCRRejectedEventPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
