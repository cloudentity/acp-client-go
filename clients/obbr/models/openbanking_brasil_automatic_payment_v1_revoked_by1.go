// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilAutomaticPaymentV1RevokedBy1 OpenbankingBrasilAutomaticPaymentV1RevokedBy1 RevokedBy1
//
// Quem iniciou a solicitao de revogao
// INICIADORA
// USUARIO
// DETENTORA
// Example: INICIADORA
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1RevokedBy1
type OpenbankingBrasilAutomaticPaymentV1RevokedBy1 string

// Validate validates this openbanking brasil automatic payment v1 revoked by1
func (m OpenbankingBrasilAutomaticPaymentV1RevokedBy1) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil automatic payment v1 revoked by1 based on context it is used
func (m OpenbankingBrasilAutomaticPaymentV1RevokedBy1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
