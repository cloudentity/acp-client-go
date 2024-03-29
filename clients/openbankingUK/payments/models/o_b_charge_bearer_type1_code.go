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

// OBChargeBearerType1Code Specifies which party/parties will bear the charges associated with the processing of the payment transaction.
//
// swagger:model OBChargeBearerType1Code
type OBChargeBearerType1Code string

func NewOBChargeBearerType1Code(value OBChargeBearerType1Code) *OBChargeBearerType1Code {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBChargeBearerType1Code.
func (m OBChargeBearerType1Code) Pointer() *OBChargeBearerType1Code {
	return &m
}

const (

	// OBChargeBearerType1CodeBorneByCreditor captures enum value "BorneByCreditor"
	OBChargeBearerType1CodeBorneByCreditor OBChargeBearerType1Code = "BorneByCreditor"

	// OBChargeBearerType1CodeBorneByDebtor captures enum value "BorneByDebtor"
	OBChargeBearerType1CodeBorneByDebtor OBChargeBearerType1Code = "BorneByDebtor"

	// OBChargeBearerType1CodeFollowingServiceLevel captures enum value "FollowingServiceLevel"
	OBChargeBearerType1CodeFollowingServiceLevel OBChargeBearerType1Code = "FollowingServiceLevel"

	// OBChargeBearerType1CodeShared captures enum value "Shared"
	OBChargeBearerType1CodeShared OBChargeBearerType1Code = "Shared"
)

// for schema
var oBChargeBearerType1CodeEnum []interface{}

func init() {
	var res []OBChargeBearerType1Code
	if err := json.Unmarshal([]byte(`["BorneByCreditor","BorneByDebtor","FollowingServiceLevel","Shared"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBChargeBearerType1CodeEnum = append(oBChargeBearerType1CodeEnum, v)
	}
}

func (m OBChargeBearerType1Code) validateOBChargeBearerType1CodeEnum(path, location string, value OBChargeBearerType1Code) error {
	if err := validate.EnumCase(path, location, value, oBChargeBearerType1CodeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b charge bearer type1 code
func (m OBChargeBearerType1Code) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBChargeBearerType1CodeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b charge bearer type1 code based on context it is used
func (m OBChargeBearerType1Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
