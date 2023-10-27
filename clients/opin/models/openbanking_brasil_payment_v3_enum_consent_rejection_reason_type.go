// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType EnumConsentRejectionReasonType
//
// Define o cdigo da razo pela qual o consentimento foi rejeitado
// VALOR_INVALIDO
// NAO_INFORMADO
// FALHA_INFRAESTRUTURA
// TEMPO_EXPIRADO_AUTORIZACAO
// TEMPO_EXPIRADO_CONSUMO
// REJEITADO_USUARIO
// CONTAS_ORIGEM_DESTINO_IGUAIS
// CONTA_NAO_PERMITE_PAGAMENTO
// SALDO_INSUFICIENTE
// VALOR_ACIMA_LIMITE
// QRCODE_INVALIDO
// Example: SALDO_INSUFICIENTE
//
// swagger:model OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType
type OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType string

// Validate validates this openbanking brasil payment v3 enum consent rejection reason type
func (m OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this openbanking brasil payment v3 enum consent rejection reason type based on context it is used
func (m OpenbankingBrasilPaymentV3EnumConsentRejectionReasonType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}