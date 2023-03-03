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

// OBInterestRateType1Code0 Rate type for overdraft fee/charge (where it is charged in terms of a rate rather than an amount)
//
// swagger:model OB_InterestRateType1Code_0
type OBInterestRateType1Code0 string

func NewOBInterestRateType1Code0(value OBInterestRateType1Code0) *OBInterestRateType1Code0 {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBInterestRateType1Code0.
func (m OBInterestRateType1Code0) Pointer() *OBInterestRateType1Code0 {
	return &m
}

const (

	// OBInterestRateType1Code0INBB captures enum value "INBB"
	OBInterestRateType1Code0INBB OBInterestRateType1Code0 = "INBB"

	// OBInterestRateType1Code0INFR captures enum value "INFR"
	OBInterestRateType1Code0INFR OBInterestRateType1Code0 = "INFR"

	// OBInterestRateType1Code0INGR captures enum value "INGR"
	OBInterestRateType1Code0INGR OBInterestRateType1Code0 = "INGR"

	// OBInterestRateType1Code0INLR captures enum value "INLR"
	OBInterestRateType1Code0INLR OBInterestRateType1Code0 = "INLR"

	// OBInterestRateType1Code0INNE captures enum value "INNE"
	OBInterestRateType1Code0INNE OBInterestRateType1Code0 = "INNE"

	// OBInterestRateType1Code0INOT captures enum value "INOT"
	OBInterestRateType1Code0INOT OBInterestRateType1Code0 = "INOT"
)

// for schema
var oBInterestRateType1Code0Enum []interface{}

func init() {
	var res []OBInterestRateType1Code0
	if err := json.Unmarshal([]byte(`["INBB","INFR","INGR","INLR","INNE","INOT"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBInterestRateType1Code0Enum = append(oBInterestRateType1Code0Enum, v)
	}
}

func (m OBInterestRateType1Code0) validateOBInterestRateType1Code0Enum(path, location string, value OBInterestRateType1Code0) error {
	if err := validate.EnumCase(path, location, value, oBInterestRateType1Code0Enum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b interest rate type1 code 0
func (m OBInterestRateType1Code0) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBInterestRateType1Code0Enum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b interest rate type1 code 0 based on context it is used
func (m OBInterestRateType1Code0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
