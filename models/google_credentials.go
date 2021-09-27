// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GoogleCredentials Google IDP specific credentials
//
// swagger:model GoogleCredentials
type GoogleCredentials struct {

	// OAuth client application secret
	ClientSecret string `json:"client_secret,omitempty"`
}

// Validate validates this google credentials
func (m *GoogleCredentials) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this google credentials based on context it is used
func (m *GoogleCredentials) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GoogleCredentials) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GoogleCredentials) UnmarshalBinary(b []byte) error {
	var res GoogleCredentials
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
