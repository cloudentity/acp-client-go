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

// OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason ConsentRejectionReason
//
// # Informaes sobre o motivo da rejeio
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason
type OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason struct {

	// code
	// Required: true
	Code *OpenbankingBrasilAutomaticPaymentV1Code4 `json:"code" yaml:"code"`

	// Detalhe sobre o motivo de rejeio indicado no campo `/data/rejection/reason/code`
	// NAO_INFORMADO: No informada pela detentora de conta;
	// FALHA_INFRAESTRUTURA: [Descrio de qual falha na infraestrutura inviabilizou o processamento];
	// TEMPO_EXPIRADO_AUTORIZACAO: Consentimento expirou antes que o usurio pudesse confirm-lo;
	// REJEITADO_USUARIO: O usurio rejeitou a autorizao do consentimento;
	// CONTAS_ORIGEM_DESTINO_IGUAIS: A conta selecionada  igual  conta destino e no permite realizar esse pagamento;
	// CONTA_NAO_PERMITE_PAGAMENTO: A conta selecionada  do tipo [salario/investimento/liquidao/outros] e no permite realizar esse pagamento;
	// SALDO_INSUFICIENTE: A conta selecionada no possui saldo suficiente para realizar o pagamento;
	// VALOR_ACIMA_LIMITE: O valor ultrapassa o limite estabelecido para permitir a realizao de transaes pelo cliente;
	// Example: O usurio rejeitou a autorizao do consentimento
	// Required: true
	// Max Length: 2048
	// Pattern: [\w\W\s]*
	Detail string `json:"detail" yaml:"detail"`
}

// Validate validates this openbanking brasil automatic payment v1 consent rejection reason
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) Validate(formats strfmt.Registry) error {
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

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) validateCode(formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) validateDetail(formats strfmt.Registry) error {

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

// ContextValidate validate this openbanking brasil automatic payment v1 consent rejection reason based on the context it is used
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCode(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) contextValidateCode(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilAutomaticPaymentV1ConsentRejectionReason
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
