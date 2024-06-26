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

// OpenbankingBrasilPaymentV4CreditorAccount OpenbankingBrasilPaymentV4CreditorAccount CreditorAccount
//
// Objeto que contm a identificao da conta de destino do beneficirio/recebedor.
//
// swagger:model OpenbankingBrasilPaymentV4CreditorAccount
type OpenbankingBrasilPaymentV4CreditorAccount struct {

	// account type
	// Required: true
	AccountType *OpenbankingBrasilPaymentV4EnumAccountPaymentsType `json:"accountType" yaml:"accountType"`

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

	// Deve ser preenchido com o nmero da conta do usurio recebedor, com dgito verificador (se este existir),
	// se houver valor alfanumrico, este deve ser convertido para 0.
	// Example: 1234567890
	// Required: true
	// Max Length: 20
	// Min Length: 1
	// Pattern: ^[0-9]{1,20}$
	Number string `json:"number" yaml:"number"`
}

// Validate validates this openbanking brasil payment v4 creditor account
func (m *OpenbankingBrasilPaymentV4CreditorAccount) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountType(formats); err != nil {
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

func (m *OpenbankingBrasilPaymentV4CreditorAccount) validateAccountType(formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4CreditorAccount) validateIspb(formats strfmt.Registry) error {

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

func (m *OpenbankingBrasilPaymentV4CreditorAccount) validateIssuer(formats strfmt.Registry) error {
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

func (m *OpenbankingBrasilPaymentV4CreditorAccount) validateNumber(formats strfmt.Registry) error {

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

// ContextValidate validate this openbanking brasil payment v4 creditor account based on the context it is used
func (m *OpenbankingBrasilPaymentV4CreditorAccount) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV4CreditorAccount) contextValidateAccountType(ctx context.Context, formats strfmt.Registry) error {

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
func (m *OpenbankingBrasilPaymentV4CreditorAccount) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV4CreditorAccount) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV4CreditorAccount
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
