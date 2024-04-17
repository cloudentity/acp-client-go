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

// OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount ConsentsDebtorAccount
//
// Objeto que contm a identificao da conta de origem do pagador. As informaes quanto  conta de origem do pagador podero ser trazidas no consentimento para a detentora, caso a iniciadora tenha coletado essas informaes do cliente.
// Do contrrio, ser coletada na detentora e trazida para a iniciadora como resposta  criao do pagamento.
//
// swagger:model OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount
type OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount struct {

	// account type
	// Required: true
	AccountType *OpenbankingBrasilAutomaticPaymentV1EnumAccountTypeConsents `json:"accountType" yaml:"accountType"`

	// Campo utilizado pela iniciadora para clculo do dia til de liquidao do pagamento (vide especificao do endToEndId) baseado no municpio de cadastro do usurio pagador no detentor.
	//
	// [Restries]
	// Campo obrigatrio que dever ser retornado quando o consentimento estiver ou passar pelo status AUTHORISED;
	// Campo obrigatrio quando o oneOf utilizado do recurringConfiguration for automatic.
	// Example: 5300108
	// Max Length: 7
	// Min Length: 7
	// Pattern: ^\d{7}$
	IbgeTownCode string `json:"ibgeTownCode,omitempty" yaml:"ibgeTownCode,omitempty"`

	// Deve ser preenchido com o ISPB (Identificador do Sistema de Pagamentos Brasileiros) do participante do SPI (Sistema de pagamentos instantneos) somente com nmeros.
	// Example: 12345678
	// Required: true
	// Max Length: 8
	// Min Length: 8
	// Pattern: ^[0-9]{8}$
	Ispb string `json:"ispb" yaml:"ispb"`

	// Cdigo da Agncia emissora da conta sem dgito.
	// (Agncia  a dependncia destinada ao atendimento aos clientes, ao pblico em geral e aos associados de cooperativas de crdito,
	// no exerccio de atividades da instituio, no podendo ser mvel ou transitria).
	//
	// [Restrio] Preenchimento obrigatrio para os seguintes tipos de conta: CACC (CONTA_DEPOSITO_A_VISTA) e SVGS (CONTA_POUPANCA).
	// Example: 1774
	// Max Length: 4
	// Min Length: 1
	// Pattern: ^[0-9]{1,4}$
	Issuer string `json:"issuer,omitempty" yaml:"issuer,omitempty"`

	// Deve ser preenchido com o nmero da conta transacional do usurio pagador, com dgito verificador (se este existir), se houver valor alfanumrico, este deve ser convertido para 0.
	// Example: 1234567890
	// Required: true
	// Max Length: 20
	// Min Length: 1
	// Pattern: ^[0-9]{1,20}$
	Number string `json:"number" yaml:"number"`
}

// Validate validates this openbanking brasil automatic payment v1 consents debtor account
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIbgeTownCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIspb(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuer(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNumber(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) validateAccountType(formats strfmt.Registry) error {

	if err := validate.Required("accountType", "body", m.AccountType); err != nil {
		return err
	}

	if err := validate.Required("accountType", "body", m.AccountType); err != nil {
		return err
	}

	if m.AccountType != nil {
		if err := m.AccountType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("accountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("accountType")
			}
			return err
		}
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) validateIbgeTownCode(formats strfmt.Registry) error {
	if swag.IsZero(m.IbgeTownCode) { // not required
		return nil
	}

	if err := validate.MinLength("ibgeTownCode", "body", m.IbgeTownCode, 7); err != nil {
		return err
	}

	if err := validate.MaxLength("ibgeTownCode", "body", m.IbgeTownCode, 7); err != nil {
		return err
	}

	if err := validate.Pattern("ibgeTownCode", "body", m.IbgeTownCode, `^\d{7}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) validateIspb(formats strfmt.Registry) error {

	if err := validate.RequiredString("ispb", "body", m.Ispb); err != nil {
		return err
	}

	if err := validate.MinLength("ispb", "body", m.Ispb, 8); err != nil {
		return err
	}

	if err := validate.MaxLength("ispb", "body", m.Ispb, 8); err != nil {
		return err
	}

	if err := validate.Pattern("ispb", "body", m.Ispb, `^[0-9]{8}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) validateIssuer(formats strfmt.Registry) error {
	if swag.IsZero(m.Issuer) { // not required
		return nil
	}

	if err := validate.MinLength("issuer", "body", m.Issuer, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("issuer", "body", m.Issuer, 4); err != nil {
		return err
	}

	if err := validate.Pattern("issuer", "body", m.Issuer, `^[0-9]{1,4}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) validateNumber(formats strfmt.Registry) error {

	if err := validate.RequiredString("number", "body", m.Number); err != nil {
		return err
	}

	if err := validate.MinLength("number", "body", m.Number, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("number", "body", m.Number, 20); err != nil {
		return err
	}

	if err := validate.Pattern("number", "body", m.Number, `^[0-9]{1,20}$`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this openbanking brasil automatic payment v1 consents debtor account based on the context it is used
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) contextValidateAccountType(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountType != nil {

		if err := m.AccountType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("accountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("accountType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilAutomaticPaymentV1ConsentsDebtorAccount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
