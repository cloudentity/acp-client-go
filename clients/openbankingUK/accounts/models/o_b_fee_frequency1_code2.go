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

// OBFeeFrequency1Code2 How frequently the fee/charge is applied to the account
//
// swagger:model OB_FeeFrequency1Code_2
type OBFeeFrequency1Code2 string

func NewOBFeeFrequency1Code2(value OBFeeFrequency1Code2) *OBFeeFrequency1Code2 {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBFeeFrequency1Code2.
func (m OBFeeFrequency1Code2) Pointer() *OBFeeFrequency1Code2 {
	return &m
}

const (

	// OBFeeFrequency1Code2FEAC captures enum value "FEAC"
	OBFeeFrequency1Code2FEAC OBFeeFrequency1Code2 = "FEAC"

	// OBFeeFrequency1Code2FEAO captures enum value "FEAO"
	OBFeeFrequency1Code2FEAO OBFeeFrequency1Code2 = "FEAO"

	// OBFeeFrequency1Code2FECP captures enum value "FECP"
	OBFeeFrequency1Code2FECP OBFeeFrequency1Code2 = "FECP"

	// OBFeeFrequency1Code2FEDA captures enum value "FEDA"
	OBFeeFrequency1Code2FEDA OBFeeFrequency1Code2 = "FEDA"

	// OBFeeFrequency1Code2FEHO captures enum value "FEHO"
	OBFeeFrequency1Code2FEHO OBFeeFrequency1Code2 = "FEHO"

	// OBFeeFrequency1Code2FEI captures enum value "FEI"
	OBFeeFrequency1Code2FEI OBFeeFrequency1Code2 = "FEI"

	// OBFeeFrequency1Code2FEMO captures enum value "FEMO"
	OBFeeFrequency1Code2FEMO OBFeeFrequency1Code2 = "FEMO"

	// OBFeeFrequency1Code2FEOA captures enum value "FEOA"
	OBFeeFrequency1Code2FEOA OBFeeFrequency1Code2 = "FEOA"

	// OBFeeFrequency1Code2FEOT captures enum value "FEOT"
	OBFeeFrequency1Code2FEOT OBFeeFrequency1Code2 = "FEOT"

	// OBFeeFrequency1Code2FEPC captures enum value "FEPC"
	OBFeeFrequency1Code2FEPC OBFeeFrequency1Code2 = "FEPC"

	// OBFeeFrequency1Code2FEPH captures enum value "FEPH"
	OBFeeFrequency1Code2FEPH OBFeeFrequency1Code2 = "FEPH"

	// OBFeeFrequency1Code2FEPO captures enum value "FEPO"
	OBFeeFrequency1Code2FEPO OBFeeFrequency1Code2 = "FEPO"

	// OBFeeFrequency1Code2FEPS captures enum value "FEPS"
	OBFeeFrequency1Code2FEPS OBFeeFrequency1Code2 = "FEPS"

	// OBFeeFrequency1Code2FEPT captures enum value "FEPT"
	OBFeeFrequency1Code2FEPT OBFeeFrequency1Code2 = "FEPT"

	// OBFeeFrequency1Code2FEPTA captures enum value "FEPTA"
	OBFeeFrequency1Code2FEPTA OBFeeFrequency1Code2 = "FEPTA"

	// OBFeeFrequency1Code2FEPTP captures enum value "FEPTP"
	OBFeeFrequency1Code2FEPTP OBFeeFrequency1Code2 = "FEPTP"

	// OBFeeFrequency1Code2FEQU captures enum value "FEQU"
	OBFeeFrequency1Code2FEQU OBFeeFrequency1Code2 = "FEQU"

	// OBFeeFrequency1Code2FESM captures enum value "FESM"
	OBFeeFrequency1Code2FESM OBFeeFrequency1Code2 = "FESM"

	// OBFeeFrequency1Code2FEST captures enum value "FEST"
	OBFeeFrequency1Code2FEST OBFeeFrequency1Code2 = "FEST"

	// OBFeeFrequency1Code2FEWE captures enum value "FEWE"
	OBFeeFrequency1Code2FEWE OBFeeFrequency1Code2 = "FEWE"

	// OBFeeFrequency1Code2FEYE captures enum value "FEYE"
	OBFeeFrequency1Code2FEYE OBFeeFrequency1Code2 = "FEYE"
)

// for schema
var oBFeeFrequency1Code2Enum []interface{}

func init() {
	var res []OBFeeFrequency1Code2
	if err := json.Unmarshal([]byte(`["FEAC","FEAO","FECP","FEDA","FEHO","FEI","FEMO","FEOA","FEOT","FEPC","FEPH","FEPO","FEPS","FEPT","FEPTA","FEPTP","FEQU","FESM","FEST","FEWE","FEYE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBFeeFrequency1Code2Enum = append(oBFeeFrequency1Code2Enum, v)
	}
}

func (m OBFeeFrequency1Code2) validateOBFeeFrequency1Code2Enum(path, location string, value OBFeeFrequency1Code2) error {
	if err := validate.EnumCase(path, location, value, oBFeeFrequency1Code2Enum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b fee frequency1 code 2
func (m OBFeeFrequency1Code2) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBFeeFrequency1Code2Enum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b fee frequency1 code 2 based on context it is used
func (m OBFeeFrequency1Code2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
