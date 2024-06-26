// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OpenbankingBrasilPaymentV4ConsentRejectionReason OpenbankingBrasilPaymentV4ConsentRejectionReason ConsentRejectionReason
//
// Motivo da rejeio do consentimento. Informaes complementares sobre o motivo do status.
//
// [Restrio] Esse motivo dever ser enviado quando o campo /data/status for igual a REJECTED.
//
// swagger:model OpenbankingBrasilPaymentV4ConsentRejectionReason
type OpenbankingBrasilPaymentV4ConsentRejectionReason struct {

	// code
	// Required: true
	Code *OpenbankingBrasilPaymentV4EnumConsentRejectionReasonType `json:"code" yaml:"code"`

	// Contm informaes adicionais ao consentimento rejeitado.
	// VALOR_INVALIDO: O valor enviado no  vlido para o QR Code informado;
	// NAO_INFORMADO: No informada pela detentora de conta;
	// FALHA_INFRAESTRUTURA: [Descrio de qual falha na infraestrutura inviabilizou o processamento].
	// TEMPO_EXPIRADO_AUTORIZACAO: Consentimento expirou antes que o usurio pudesse confirm-lo.
	// TEMPO_EXPIRADO_CONSUMO: O usurio no finalizou o fluxo de pagamento e o consentimento expirou;
	// REJEITADO_USUARIO: O usurio rejeitou a autorizao do consentimento
	// CONTAS_ORIGEM_DESTINO_IGUAIS: A conta selecionada  igual  conta destino e no permite realizar esse pagamento.
	// CONTA_NAO_PERMITE_PAGAMENTO: A conta selecionada  do tipo [salario/investimento/liquidao/outros] e no permite realizar esse pagamento.
	// SALDO_INSUFICIENTE: A conta selecionada no possui saldo suficiente para realizar o pagamento.
	// VALOR_ACIMA_LIMITE: O valor ultrapassa o limite estabelecido [na instituio/no arranjo/outro] para permitir a realizao de transaes pelo cliente.
	// QRCODE_INVALIDO: O QRCode utilizado para a iniciao de pagamento no  vlido.
	//
	// [Restrio] Caso consentimento rejeitado de verses nas quais no havia o campo rejectionReason retornar o seguinte detail: Motivo de rejeio inexistente em verses anteriores.
	// Example: O usurio rejeitou a autorizao do consentimento
	// Required: true
	// Max Length: 2048
	// Pattern: [\w\W\s]*
	Detail string `json:"detail" yaml:"detail"`
}

// Validate validates this openbanking brasil payment v4 consent rejection reason
func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetail(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) validateCode(formats strfmt.Registry) error {

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	if err := validate.Required("code", "body", m.Code); err != nil {
		return err
	}

	if m.Code != nil {
		if err := m.Code.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) validateDetail(formats strfmt.Registry) error {

	if err := validate.RequiredString("detail", "body", m.Detail); err != nil {
		return err
	}

	if err := validate.MaxLength("detail", "body", m.Detail, 2048); err != nil {
		return err
	}

	if err := validate.Pattern("detail", "body", m.Detail, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil payment v4 consent rejection reason based on the context it is used
func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) contextValidateCode(ctx context.Context, formats strfmt.Registry) error {

	if m.Code != nil {

		if err := m.Code.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("code")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("code")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4ConsentRejectionReason) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV4ConsentRejectionReason
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
