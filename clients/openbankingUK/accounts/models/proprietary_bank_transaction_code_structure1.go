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

// ProprietaryBankTransactionCodeStructure1 Set of elements to fully identify a proprietary bank transaction code.
//
// swagger:model ProprietaryBankTransactionCodeStructure1
type ProprietaryBankTransactionCodeStructure1 struct {

	// Proprietary bank transaction code to identify the underlying transaction.
	// Required: true
	// Max Length: 35
	// Min Length: 1
	Code string `json:"Code"`

	// Identification of the issuer of the proprietary bank transaction code.
	// Max Length: 35
	// Min Length: 1
	Issuer string `json:"Issuer,omitempty"`
}

// Validate validates this proprietary bank transaction code structure1
func (m *ProprietaryBankTransactionCodeStructure1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIssuer(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProprietaryBankTransactionCodeStructure1) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("Code", "body", m.Code); err != nil {
		return err
	}

	if err := validate.MinLength("Code", "body", m.Code, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Code", "body", m.Code, 35); err != nil {
		return err
	}

	return nil
}

func (m *ProprietaryBankTransactionCodeStructure1) validateIssuer(formats strfmt.Registry) error {
	if swag.IsZero(m.Issuer) { // not required
		return nil
	}

	if err := validate.MinLength("Issuer", "body", m.Issuer, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Issuer", "body", m.Issuer, 35); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this proprietary bank transaction code structure1 based on context it is used
func (m *ProprietaryBankTransactionCodeStructure1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ProprietaryBankTransactionCodeStructure1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProprietaryBankTransactionCodeStructure1) UnmarshalBinary(b []byte) error {
	var res ProprietaryBankTransactionCodeStructure1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
