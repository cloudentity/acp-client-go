// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// OBCreditDebitCode2 Indicates whether the balance is a credit or a debit balance.
// Usage: A zero balance is considered to be a credit balance.
//
// swagger:model OBCreditDebitCode_2
type OBCreditDebitCode2 string

func NewOBCreditDebitCode2(value OBCreditDebitCode2) *OBCreditDebitCode2 {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBCreditDebitCode2.
func (m OBCreditDebitCode2) Pointer() *OBCreditDebitCode2 {
	return &m
}

const (

	// OBCreditDebitCode2Credit captures enum value "Credit"
	OBCreditDebitCode2Credit OBCreditDebitCode2 = "Credit"

	// OBCreditDebitCode2Debit captures enum value "Debit"
	OBCreditDebitCode2Debit OBCreditDebitCode2 = "Debit"
)

// for schema
var oBCreditDebitCode2Enum []interface{}

func init() {
	var res []OBCreditDebitCode2
	if err := json.Unmarshal([]byte(`["Credit","Debit"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBCreditDebitCode2Enum = append(oBCreditDebitCode2Enum, v)
	}
}

func (m OBCreditDebitCode2) validateOBCreditDebitCode2Enum(path, location string, value OBCreditDebitCode2) error {
	if err := validate.EnumCase(path, location, value, oBCreditDebitCode2Enum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b credit debit code 2
func (m OBCreditDebitCode2) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBCreditDebitCode2Enum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b credit debit code 2 based on context it is used
func (m OBCreditDebitCode2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
