// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DeviceResponse Device Response
//
// swagger:model DeviceResponse
type DeviceResponse struct {

	// The device verification code.
	DeviceCode string `json:"device_code,omitempty" yaml:"device_code,omitempty"`

	// The lifetime in seconds of the "device_code" and "user_code".
	ExpiresIn int64 `json:"expires_in,omitempty" yaml:"expires_in,omitempty"`

	// The minimum amount of time in seconds that the client
	// SHOULD wait between polling requests to the token endpoint.  If no
	// value is provided, clients MUST use 5 as the default.
	Interval int64 `json:"interval,omitempty" yaml:"interval,omitempty"`

	// The end-user verification code.
	UserCode string `json:"user_code,omitempty" yaml:"user_code,omitempty"`

	// The end-user verification URI on the authorization server.
	// The URI should be short and easy to remember as end users will be asked to manually type it into their user agent.
	VerificationURI string `json:"verification_uri,omitempty" yaml:"verification_uri,omitempty"`

	// A verification URI that includes the "user_code" (or other information with the same function as the "user_code"),
	// which is designed for non-textual transmission.
	VerificationURIComplete string `json:"verification_uri_complete,omitempty" yaml:"verification_uri_complete,omitempty"`
}

// Validate validates this device response
func (m *DeviceResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this device response based on context it is used
func (m *DeviceResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeviceResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeviceResponse) UnmarshalBinary(b []byte) error {
	var res DeviceResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
