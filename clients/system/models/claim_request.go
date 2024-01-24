// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ClaimRequest claim request
//
// swagger:model ClaimRequest
type ClaimRequest struct {

	// essential
	Essential bool `json:"essential,omitempty" yaml:"essential,omitempty"`

	// value
	Value interface{} `json:"value,omitempty" yaml:"value,omitempty"`

	// values
	Values []interface{} `json:"values" yaml:"values"`
}

// Validate validates this claim request
func (m *ClaimRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this claim request based on context it is used
func (m *ClaimRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ClaimRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ClaimRequest) UnmarshalBinary(b []byte) error {
	var res ClaimRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
