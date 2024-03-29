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

// OBExternalAccountSubType1Code Specifies the sub type of account (product family group).
//
// swagger:model OBExternalAccountSubType1Code
type OBExternalAccountSubType1Code string

func NewOBExternalAccountSubType1Code(value OBExternalAccountSubType1Code) *OBExternalAccountSubType1Code {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBExternalAccountSubType1Code.
func (m OBExternalAccountSubType1Code) Pointer() *OBExternalAccountSubType1Code {
	return &m
}

const (

	// OBExternalAccountSubType1CodeChargeCard captures enum value "ChargeCard"
	OBExternalAccountSubType1CodeChargeCard OBExternalAccountSubType1Code = "ChargeCard"

	// OBExternalAccountSubType1CodeCreditCard captures enum value "CreditCard"
	OBExternalAccountSubType1CodeCreditCard OBExternalAccountSubType1Code = "CreditCard"

	// OBExternalAccountSubType1CodeCurrentAccount captures enum value "CurrentAccount"
	OBExternalAccountSubType1CodeCurrentAccount OBExternalAccountSubType1Code = "CurrentAccount"

	// OBExternalAccountSubType1CodeEMoney captures enum value "EMoney"
	OBExternalAccountSubType1CodeEMoney OBExternalAccountSubType1Code = "EMoney"

	// OBExternalAccountSubType1CodeLoan captures enum value "Loan"
	OBExternalAccountSubType1CodeLoan OBExternalAccountSubType1Code = "Loan"

	// OBExternalAccountSubType1CodeMortgage captures enum value "Mortgage"
	OBExternalAccountSubType1CodeMortgage OBExternalAccountSubType1Code = "Mortgage"

	// OBExternalAccountSubType1CodePrePaidCard captures enum value "PrePaidCard"
	OBExternalAccountSubType1CodePrePaidCard OBExternalAccountSubType1Code = "PrePaidCard"

	// OBExternalAccountSubType1CodeSavings captures enum value "Savings"
	OBExternalAccountSubType1CodeSavings OBExternalAccountSubType1Code = "Savings"
)

// for schema
var oBExternalAccountSubType1CodeEnum []interface{}

func init() {
	var res []OBExternalAccountSubType1Code
	if err := json.Unmarshal([]byte(`["ChargeCard","CreditCard","CurrentAccount","EMoney","Loan","Mortgage","PrePaidCard","Savings"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBExternalAccountSubType1CodeEnum = append(oBExternalAccountSubType1CodeEnum, v)
	}
}

func (m OBExternalAccountSubType1Code) validateOBExternalAccountSubType1CodeEnum(path, location string, value OBExternalAccountSubType1Code) error {
	if err := validate.EnumCase(path, location, value, oBExternalAccountSubType1CodeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b external account sub type1 code
func (m OBExternalAccountSubType1Code) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBExternalAccountSubType1CodeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b external account sub type1 code based on context it is used
func (m OBExternalAccountSubType1Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
