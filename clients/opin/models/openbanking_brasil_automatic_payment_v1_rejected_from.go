// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilAutomaticPaymentV1RejectedFrom OpenbankingBrasilAutomaticPaymentV1RejectedFrom RejectedFrom
//
// Canal onde iniciou-se o processo de rejeio
// INICIADORA
// DETENTORA
// Example: DETENTORA
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1RejectedFrom
type OpenbankingBrasilAutomaticPaymentV1RejectedFrom string

// Validate validates this openbanking brasil automatic payment v1 rejected from
func (m OpenbankingBrasilAutomaticPaymentV1RejectedFrom) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil automatic payment v1 rejected from based on context it is used
func (m OpenbankingBrasilAutomaticPaymentV1RejectedFrom) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
