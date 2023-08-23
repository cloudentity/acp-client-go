// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OPINStatus OPINStatus Status
//
// Estado atual do consentimento cadastrado.
// Example: AWAITING_AUTHORISATION
//
// swagger:model OPINStatus
type OPINStatus string

// Validate validates this o p i n status
func (m OPINStatus) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this o p i n status based on context it is used
func (m OPINStatus) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}