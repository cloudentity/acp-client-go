// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// TownName TownName Name of a built-up area, with defined boundaries, and a local government.
//
// swagger:model TownName
type TownName string

// Validate validates this town name
func (m TownName) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this town name based on context it is used
func (m TownName) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
