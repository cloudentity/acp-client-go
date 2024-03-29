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

// OBExternalScheduleType1Code Specifies the scheduled payment date type requested
//
// swagger:model OBExternalScheduleType1Code
type OBExternalScheduleType1Code string

func NewOBExternalScheduleType1Code(value OBExternalScheduleType1Code) *OBExternalScheduleType1Code {
	return &value
}

// Pointer returns a pointer to a freshly-allocated OBExternalScheduleType1Code.
func (m OBExternalScheduleType1Code) Pointer() *OBExternalScheduleType1Code {
	return &m
}

const (

	// OBExternalScheduleType1CodeArrival captures enum value "Arrival"
	OBExternalScheduleType1CodeArrival OBExternalScheduleType1Code = "Arrival"

	// OBExternalScheduleType1CodeExecution captures enum value "Execution"
	OBExternalScheduleType1CodeExecution OBExternalScheduleType1Code = "Execution"
)

// for schema
var oBExternalScheduleType1CodeEnum []interface{}

func init() {
	var res []OBExternalScheduleType1Code
	if err := json.Unmarshal([]byte(`["Arrival","Execution"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBExternalScheduleType1CodeEnum = append(oBExternalScheduleType1CodeEnum, v)
	}
}

func (m OBExternalScheduleType1Code) validateOBExternalScheduleType1CodeEnum(path, location string, value OBExternalScheduleType1Code) error {
	if err := validate.EnumCase(path, location, value, oBExternalScheduleType1CodeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this o b external schedule type1 code
func (m OBExternalScheduleType1Code) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateOBExternalScheduleType1CodeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this o b external schedule type1 code based on context it is used
func (m OBExternalScheduleType1Code) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
