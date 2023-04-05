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

// OpenbankingBrasilPaymentDetails OpenbankingBrasilPaymentDetails Details
//
// Objeto contendo os detalhes do pagamento.
//
// swagger:model OpenbankingBrasilPaymentDetails
type OpenbankingBrasilPaymentDetails struct {

	// creditor account
	// Required: true
	CreditorAccount *OpenbankingBrasilPaymentCreditorAccount `json:"creditorAccount"`

	// local instrument
	// Required: true
	LocalInstrument *OpenbankingBrasilPaymentEnumLocalInstrument `json:"localInstrument"`

	// Chave cadastrada no DICT pertencente ao recebedor. Os tipos de chaves podem ser: telefone, e-mail, cpf/cnpj ou chave aleatria.
	// No caso de telefone celular deve ser informado no padro E.1641.
	// Para e-mail deve ter o formato xxxxxxxx@xxxxxxx.xxx(.xx) e no mximo 77 caracteres.
	// No caso de CPF dever ser informado com 11 nmeros, sem pontos ou traos.
	// Para o caso de CNPJ dever ser informado com 14 nmeros, sem pontos ou traos.
	// No caso de chave aleatria deve ser informado o UUID gerado pelo DICT, conforme formato especificado na RFC41223.
	// Se informado, a detentora da conta deve validar o proxy no DICT quando localInstrument for igual a DICT, QRDN ou QRES e validar o campo creditorAccount.
	// Esta validao  opcional caso o localInstrument for igual a INIC.
	// [Restrio]
	// Se localInstrument for igual a MANU, o campo proxy no deve ser preenchido.
	// Se localInstrument for igual INIC, DICT, QRDN ou QRES, o campo proxy deve ser sempre preenchido com a chave Pix.
	// Example: 12345678901
	// Max Length: 77
	// Pattern: [\w\W\s]*
	Proxy string `json:"proxy,omitempty"`

	// Sequncia de caracteres que corresponde ao QR Code disponibilizado para o pagador.
	//
	// a sequncia de caracteres que seria lida pelo leitor de QR Code, e deve propiciar o retorno dos dados do pagador aps consulta na DICT.
	//
	// Essa funcionalidade  possvel tanto para QR Code esttico quanto para QR Code dinmico.
	// No arranjo do Pix esta  a mesma sequncia gerada e/ou lida pela funcionalidade Pix Copia e Cola.
	// Este campo dever ser no formato UTF-8.
	// [Restrio] Preenchimento obrigatrio para pagamentos por QR Code, observado o tamanho mximo de 512 bytes.
	// Example: 00020104141234567890123426660014BR.GOV.BCB.PIX014466756C616E6F32303139406578616D706C652E636F6D27300012\\nBR.COM.OUTRO011001234567895204000053039865406123.455802BR5915NOMEDORECEBEDOR6008BRASILIA61087007490062\\n530515RP12345678-201950300017BR.GOV.BCB.BRCODE01051.0.080450014BR.GOV.BCB.PIX0123PADRAO.URL.PIX/0123AB\\nCD81390012BR.COM.OUTRO01190123.ABCD.3456.WXYZ6304EB76\\n
	// Max Length: 512
	// Pattern: [\w\W\s]*
	QrCode string `json:"qrCode,omitempty"`
}

// Validate validates this openbanking brasil payment details
func (m *OpenbankingBrasilPaymentDetails) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreditorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLocalInstrument(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProxy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQrCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentDetails) validateCreditorAccount(formats strfmt.Registry) error {

	if err := validate.Required("creditorAccount", "body", m.CreditorAccount); err != nil {
		return err
	}

	if m.CreditorAccount != nil {
		if err := m.CreditorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("creditorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("creditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentDetails) validateLocalInstrument(formats strfmt.Registry) error {

	if err := validate.Required("localInstrument", "body", m.LocalInstrument); err != nil {
		return err
	}

	if err := validate.Required("localInstrument", "body", m.LocalInstrument); err != nil {
		return err
	}

	if m.LocalInstrument != nil {
		if err := m.LocalInstrument.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("localInstrument")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("localInstrument")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentDetails) validateProxy(formats strfmt.Registry) error {
	if swag.IsZero(m.Proxy) { // not required
		return nil
	}

	if err := validate.MaxLength("proxy", "body", m.Proxy, 77); err != nil {
		return err
	}

	if err := validate.Pattern("proxy", "body", m.Proxy, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentDetails) validateQrCode(formats strfmt.Registry) error {
	if swag.IsZero(m.QrCode) { // not required
		return nil
	}

	if err := validate.MaxLength("qrCode", "body", m.QrCode, 512); err != nil {
		return err
	}

	if err := validate.Pattern("qrCode", "body", m.QrCode, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil payment details based on the context it is used
func (m *OpenbankingBrasilPaymentDetails) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCreditorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLocalInstrument(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentDetails) contextValidateCreditorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.CreditorAccount != nil {
		if err := m.CreditorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("creditorAccount")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("creditorAccount")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilPaymentDetails) contextValidateLocalInstrument(ctx context.Context, formats strfmt.Registry) error {

	if m.LocalInstrument != nil {
		if err := m.LocalInstrument.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("localInstrument")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("localInstrument")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentDetails) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentDetails) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentDetails
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
