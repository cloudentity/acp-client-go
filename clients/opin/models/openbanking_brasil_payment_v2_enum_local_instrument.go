// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilPaymentV2EnumLocalInstrument OpenbankingBrasilPaymentV2EnumLocalInstrument EnumLocalInstrument
//
// Especifica a forma de iniciao do pagamento:
// MANU - Insero manual de dados da conta transacional
// DICT - Insero manual de chave Pix
// QRDN - QR code dinmico
// QRES - QR code esttico
// INIC - Indica que o recebedor (creditor) contratou o Iniciador de Pagamentos especificamente para realizar iniciaes de pagamento em que o beneficirio  previamente conhecido.
// Example: DICT
//
// swagger:model OpenbankingBrasilPaymentV2EnumLocalInstrument
type OpenbankingBrasilPaymentV2EnumLocalInstrument string

// Validate validates this openbanking brasil payment v2 enum local instrument
func (m OpenbankingBrasilPaymentV2EnumLocalInstrument) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil payment v2 enum local instrument based on context it is used
func (m OpenbankingBrasilPaymentV2EnumLocalInstrument) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
