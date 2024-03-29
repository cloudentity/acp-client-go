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

// OBBankTransactionCodeStructure1 Set of elements used to fully identify the type of underlying transaction resulting in an entry.
//
// swagger:model OBBankTransactionCodeStructure1
type OBBankTransactionCodeStructure1 struct {

	// Specifies the family within a domain.
	// Required: true
	// Max Length: 4
	// Min Length: 1
	Code string `json:"Code"`

	// Specifies the sub-product family within a specific family.
	// Required: true
	// Max Length: 4
	// Min Length: 1
	SubCode string `json:"SubCode"`
}

// Validate validates this o b bank transaction code structure1
func (m *OBBankTransactionCodeStructure1) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubCode(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OBBankTransactionCodeStructure1) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("Code", "body", m.Code); err != nil {
		return err
	}

	if err := validate.MinLength("Code", "body", m.Code, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("Code", "body", m.Code, 4); err != nil {
		return err
	}

	return nil
}

func (m *OBBankTransactionCodeStructure1) validateSubCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("SubCode", "body", m.SubCode); err != nil {
		return err
	}

	if err := validate.MinLength("SubCode", "body", m.SubCode, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("SubCode", "body", m.SubCode, 4); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b bank transaction code structure1 based on context it is used
func (m *OBBankTransactionCodeStructure1) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBBankTransactionCodeStructure1) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBBankTransactionCodeStructure1) UnmarshalBinary(b []byte) error {
	var res OBBankTransactionCodeStructure1
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
