// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// Department Department Identification of a division of a large organisation or building.
//
// swagger:model Department
type Department string

// Validate validates this department
func (m Department) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this department based on context it is used
func (m Department) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
