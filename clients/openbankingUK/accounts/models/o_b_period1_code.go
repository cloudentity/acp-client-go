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

// OBPeriod1Code Period e.g. day, week, month etc. for which the fee/charge is capped
//
// swagger:model OB_Period1Code
type OBPeriod1Code string

func NewOBPeriod1Code(value OBPeriod1Code) *OBPeriod1Code {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBPeriod1Code.
func (m OBPeriod1Code) Pointer() *OBPeriod1Code {
	return &m
}

const (

	// OBPeriod1CodePACT captures enum value "PACT"
	OBPeriod1CodePACT OBPeriod1Code = "PACT"

	// OBPeriod1CodePDAY captures enum value "PDAY"
	OBPeriod1CodePDAY OBPeriod1Code = "PDAY"

	// OBPeriod1CodePHYR captures enum value "PHYR"
	OBPeriod1CodePHYR OBPeriod1Code = "PHYR"

	// OBPeriod1CodePMTH captures enum value "PMTH"
	OBPeriod1CodePMTH OBPeriod1Code = "PMTH"

	// OBPeriod1CodePQTR captures enum value "PQTR"
	OBPeriod1CodePQTR OBPeriod1Code = "PQTR"

	// OBPeriod1CodePWEK captures enum value "PWEK"
	OBPeriod1CodePWEK OBPeriod1Code = "PWEK"

	// OBPeriod1CodePYER captures enum value "PYER"
	OBPeriod1CodePYER OBPeriod1Code = "PYER"
)

// for schema
var oBPeriod1CodeEnum []interface{}

func init() {
	var res []OBPeriod1Code
	if err := json.Unmarshal([]byte(`["PACT","PDAY","PHYR","PMTH","PQTR","PWEK","PYER"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBPeriod1CodeEnum = append(oBPeriod1CodeEnum, v)
	}
}

func (m OBPeriod1Code) validateOBPeriod1CodeEnum(path, location string, value OBPeriod1Code) error {
	if err := validate.EnumCase(path, location, value, oBPeriod1CodeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b period1 code
func (m OBPeriod1Code) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBPeriod1CodeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b period1 code based on context it is used
func (m OBPeriod1Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
