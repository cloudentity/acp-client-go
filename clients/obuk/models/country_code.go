// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// CountryCode CountryCode Nation with its own government.
//
// swagger:model CountryCode
type CountryCode string

// Validate validates this country code
func (m CountryCode) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this country code based on context it is used
func (m CountryCode) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
