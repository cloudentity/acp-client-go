// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// ConsentStatus consent status
//
// swagger:model ConsentStatus
type ConsentStatus string

// Validate validates this consent status
func (m ConsentStatus) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this consent status based on context it is used
func (m ConsentStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}