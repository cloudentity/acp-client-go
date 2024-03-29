// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// AuthenticationMechanisms AuthenticationMechanisms authentication mechanisms
//
// swagger:model AuthenticationMechanisms
type AuthenticationMechanisms []string

// Validate validates this authentication mechanisms
func (m AuthenticationMechanisms) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this authentication mechanisms based on context it is used
func (m AuthenticationMechanisms) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
