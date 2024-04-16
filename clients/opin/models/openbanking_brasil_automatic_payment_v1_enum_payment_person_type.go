// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType EnumPaymentPersonType
//
// Titular, pessoa natural ou juridica a quem se referem os dados de recebedor (creditor).
// Example: PESSOA_NATURAL
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType
type OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType string

// Validate validates this openbanking brasil automatic payment v1 enum payment person type
func (m OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil automatic payment v1 enum payment person type based on context it is used
func (m OpenbankingBrasilAutomaticPaymentV1EnumPaymentPersonType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
