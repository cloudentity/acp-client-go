// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PIICategory p i i category
//
// swagger:model PIICategory
type PIICategory struct {

	// name
	// Example: HIPAA
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// Validate validates this p i i category
func (m *PIICategory) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this p i i category based on context it is used
func (m *PIICategory) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PIICategory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PIICategory) UnmarshalBinary(b []byte) error {
	var res PIICategory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
