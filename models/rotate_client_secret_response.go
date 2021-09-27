// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RotateClientSecretResponse rotate client secret response
//
// swagger:model RotateClientSecretResponse
type RotateClientSecretResponse struct {

	// secret
	Secret string `json:"secret,omitempty"`
}

// Validate validates this rotate client secret response
func (m *RotateClientSecretResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this rotate client secret response based on context it is used
func (m *RotateClientSecretResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RotateClientSecretResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RotateClientSecretResponse) UnmarshalBinary(b []byte) error {
	var res RotateClientSecretResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
