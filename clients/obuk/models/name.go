// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// Name Name Name by which an agent is known and which is usually used to identify that agent.
//
// swagger:model Name
type Name string

// Validate validates this name
func (m Name) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this name based on context it is used
func (m Name) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
