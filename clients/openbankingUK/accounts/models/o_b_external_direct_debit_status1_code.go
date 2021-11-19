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

// OBExternalDirectDebitStatus1Code Specifies the status of the direct debit in code form.
//
// swagger:model OBExternalDirectDebitStatus1Code
type OBExternalDirectDebitStatus1Code string

func NewOBExternalDirectDebitStatus1Code(value OBExternalDirectDebitStatus1Code) *OBExternalDirectDebitStatus1Code {
	v := value
	return &v
}

const (

	// OBExternalDirectDebitStatus1CodeActive captures enum value "Active"
	OBExternalDirectDebitStatus1CodeActive OBExternalDirectDebitStatus1Code = "Active"

	// OBExternalDirectDebitStatus1CodeInactive captures enum value "Inactive"
	OBExternalDirectDebitStatus1CodeInactive OBExternalDirectDebitStatus1Code = "Inactive"
)

// for schema
var oBExternalDirectDebitStatus1CodeEnum []interface{}

func init() {
	var res []OBExternalDirectDebitStatus1Code
	if err := json.Unmarshal([]byte(`["Active","Inactive"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBExternalDirectDebitStatus1CodeEnum = append(oBExternalDirectDebitStatus1CodeEnum, v)
	}
}

func (m OBExternalDirectDebitStatus1Code) validateOBExternalDirectDebitStatus1CodeEnum(path, location string, value OBExternalDirectDebitStatus1Code) error {
	if err := validate.EnumCase(path, location, value, oBExternalDirectDebitStatus1CodeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b external direct debit status1 code
func (m OBExternalDirectDebitStatus1Code) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBExternalDirectDebitStatus1CodeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b external direct debit status1 code based on context it is used
func (m OBExternalDirectDebitStatus1Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}