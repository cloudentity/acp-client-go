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

// OBFeeFrequency1Code0 Frequency at which the overdraft charge is applied to the account
//
// swagger:model OB_FeeFrequency1Code_0
type OBFeeFrequency1Code0 string

func NewOBFeeFrequency1Code0(value OBFeeFrequency1Code0) *OBFeeFrequency1Code0 {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBFeeFrequency1Code0.
func (m OBFeeFrequency1Code0) Pointer() *OBFeeFrequency1Code0 {
	return &m
}

const (

	// OBFeeFrequency1Code0FEAC captures enum value "FEAC"
	OBFeeFrequency1Code0FEAC OBFeeFrequency1Code0 = "FEAC"

	// OBFeeFrequency1Code0FEAO captures enum value "FEAO"
	OBFeeFrequency1Code0FEAO OBFeeFrequency1Code0 = "FEAO"

	// OBFeeFrequency1Code0FECP captures enum value "FECP"
	OBFeeFrequency1Code0FECP OBFeeFrequency1Code0 = "FECP"

	// OBFeeFrequency1Code0FEDA captures enum value "FEDA"
	OBFeeFrequency1Code0FEDA OBFeeFrequency1Code0 = "FEDA"

	// OBFeeFrequency1Code0FEHO captures enum value "FEHO"
	OBFeeFrequency1Code0FEHO OBFeeFrequency1Code0 = "FEHO"

	// OBFeeFrequency1Code0FEI captures enum value "FEI"
	OBFeeFrequency1Code0FEI OBFeeFrequency1Code0 = "FEI"

	// OBFeeFrequency1Code0FEMO captures enum value "FEMO"
	OBFeeFrequency1Code0FEMO OBFeeFrequency1Code0 = "FEMO"

	// OBFeeFrequency1Code0FEOA captures enum value "FEOA"
	OBFeeFrequency1Code0FEOA OBFeeFrequency1Code0 = "FEOA"

	// OBFeeFrequency1Code0FEOT captures enum value "FEOT"
	OBFeeFrequency1Code0FEOT OBFeeFrequency1Code0 = "FEOT"

	// OBFeeFrequency1Code0FEPC captures enum value "FEPC"
	OBFeeFrequency1Code0FEPC OBFeeFrequency1Code0 = "FEPC"

	// OBFeeFrequency1Code0FEPH captures enum value "FEPH"
	OBFeeFrequency1Code0FEPH OBFeeFrequency1Code0 = "FEPH"

	// OBFeeFrequency1Code0FEPO captures enum value "FEPO"
	OBFeeFrequency1Code0FEPO OBFeeFrequency1Code0 = "FEPO"

	// OBFeeFrequency1Code0FEPS captures enum value "FEPS"
	OBFeeFrequency1Code0FEPS OBFeeFrequency1Code0 = "FEPS"

	// OBFeeFrequency1Code0FEPT captures enum value "FEPT"
	OBFeeFrequency1Code0FEPT OBFeeFrequency1Code0 = "FEPT"

	// OBFeeFrequency1Code0FEPTA captures enum value "FEPTA"
	OBFeeFrequency1Code0FEPTA OBFeeFrequency1Code0 = "FEPTA"

	// OBFeeFrequency1Code0FEPTP captures enum value "FEPTP"
	OBFeeFrequency1Code0FEPTP OBFeeFrequency1Code0 = "FEPTP"

	// OBFeeFrequency1Code0FEQU captures enum value "FEQU"
	OBFeeFrequency1Code0FEQU OBFeeFrequency1Code0 = "FEQU"

	// OBFeeFrequency1Code0FESM captures enum value "FESM"
	OBFeeFrequency1Code0FESM OBFeeFrequency1Code0 = "FESM"

	// OBFeeFrequency1Code0FEST captures enum value "FEST"
	OBFeeFrequency1Code0FEST OBFeeFrequency1Code0 = "FEST"

	// OBFeeFrequency1Code0FEWE captures enum value "FEWE"
	OBFeeFrequency1Code0FEWE OBFeeFrequency1Code0 = "FEWE"

	// OBFeeFrequency1Code0FEYE captures enum value "FEYE"
	OBFeeFrequency1Code0FEYE OBFeeFrequency1Code0 = "FEYE"
)

// for schema
var oBFeeFrequency1Code0Enum []interface{}

func init() {
	var res []OBFeeFrequency1Code0
	if err := json.Unmarshal([]byte(`["FEAC","FEAO","FECP","FEDA","FEHO","FEI","FEMO","FEOA","FEOT","FEPC","FEPH","FEPO","FEPS","FEPT","FEPTA","FEPTP","FEQU","FESM","FEST","FEWE","FEYE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBFeeFrequency1Code0Enum = append(oBFeeFrequency1Code0Enum, v)
	}
}

func (m OBFeeFrequency1Code0) validateOBFeeFrequency1Code0Enum(path, location string, value OBFeeFrequency1Code0) error {
	if err := validate.EnumCase(path, location, value, oBFeeFrequency1Code0Enum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b fee frequency1 code 0
func (m OBFeeFrequency1Code0) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBFeeFrequency1Code0Enum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b fee frequency1 code 0 based on context it is used
func (m OBFeeFrequency1Code0) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
