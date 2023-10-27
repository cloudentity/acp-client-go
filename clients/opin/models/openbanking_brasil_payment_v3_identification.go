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

// OpenbankingBrasilPaymentV3Identification OpenbankingBrasilPaymentV3Identification Identification
//
// Objeto contendo os dados do recebedor (creditor).
//
// swagger:model OpenbankingBrasilPaymentV3Identification
type OpenbankingBrasilPaymentV3Identification struct {

	// Identificao da pessoa envolvida na transao.
	// Preencher com o CPF ou CNPJ, de acordo com o valor escolhido no campo type.
	// O CPF ser utilizado com 11 nmeros e dever ser informado sem pontos ou traos.
	// O CNPJ ser utilizado com 14 nmeros e dever ser informado sem pontos ou traos.
	// Example: 58764789000137
	// Required: true
	// Max Length: 14
	// Min Length: 11
	// Pattern: ^\d{11}$|^\d{14}$
	CpfCnpj string `json:"cpfCnpj"`

	// Em caso de pessoa natural deve ser informado o nome completo do titular da conta do recebedor.
	// Em caso de pessoa jurdica deve ser informada a razo social ou o nome fantasia da conta do recebedor.
	// Example: Marco Antonio de Brito
	// Required: true
	// Max Length: 120
	// Pattern: ^([A-Za-z---,.@:&*+_<>()!?/\\$%\d' -]+)$
	Name string `json:"name"`

	// person type
	// Required: true
	PersonType *OpenbankingBrasilPaymentV3EnumPaymentPersonType `json:"personType"`
}

// Validate validates this openbanking brasil payment v3 identification
func (m *OpenbankingBrasilPaymentV3Identification) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCpfCnpj(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePersonType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV3Identification) validateCpfCnpj(formats strfmt.Registry) error {

	if err := validate.RequiredString("cpfCnpj", "body", m.CpfCnpj); err != nil {
		return err
	}

	if err := validate.MinLength("cpfCnpj", "body", m.CpfCnpj, 11); err != nil {
		return err
	}

	if err := validate.MaxLength("cpfCnpj", "body", m.CpfCnpj, 14); err != nil {
		return err
	}

	if err := validate.Pattern("cpfCnpj", "body", m.CpfCnpj, `^\d{11}$|^\d{14}$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV3Identification) validateName(formats strfmt.Registry) error {

	if err := validate.RequiredString("name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.MaxLength("name", "body", m.Name, 120); err != nil {
		return err
	}

	if err := validate.Pattern("name", "body", m.Name, `^([A-Za-z---,.@:&*+_<>()!?/\\$%\d' -]+)$`); err != nil {
		return err
	}

	return nil
}

func (m *OpenbankingBrasilPaymentV3Identification) validatePersonType(formats strfmt.Registry) error {

	if err := validate.Required("personType", "body", m.PersonType); err != nil {
		return err
	}

	if err := validate.Required("personType", "body", m.PersonType); err != nil {
		return err
	}

	if m.PersonType != nil {
		if err := m.PersonType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("personType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("personType")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this openbanking brasil payment v3 identification based on the context it is used
func (m *OpenbankingBrasilPaymentV3Identification) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePersonType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OpenbankingBrasilPaymentV3Identification) contextValidatePersonType(ctx context.Context, formats strfmt.Registry) error {

	if m.PersonType != nil {

		if err := m.PersonType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("personType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("personType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV3Identification) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OpenbankingBrasilPaymentV3Identification) UnmarshalBinary(b []byte) error {
	var res OpenbankingBrasilPaymentV3Identification
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}