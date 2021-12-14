// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PARResponse Pushed Authentication Response
//
// swagger:model PARResponse
type PARResponse struct {

	// A JSON number that represents the lifetime of the request URI in seconds as a positive integer.
	// The request URI lifetime is at the discretion of the authorization server but will typically be
	// relatively short (e.g., between 5 and 600 seconds).
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// The request URI corresponding to the authorization request posted.
	// This URI is a single-use reference to the respective request data in the subsequent authorization request.
	// The way the authorization process obtains the authorization request data is at the discretion of the
	// authorization server and is out of scope of this specification.
	// There is no need to make the authorization request data available to other parties via this URI.
	RequestURI string `json:"request_uri,omitempty"`
}

// Validate validates this p a r response
func (m *PARResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this p a r response based on context it is used
func (m *PARResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PARResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PARResponse) UnmarshalBinary(b []byte) error {
	var res PARResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}