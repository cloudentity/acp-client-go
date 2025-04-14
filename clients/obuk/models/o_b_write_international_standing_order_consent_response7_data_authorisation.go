// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation The authorisation type request from the TPP.
//
// swagger:model OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation
type OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation struct {

	// Type of authorisation flow requested.
	// Required: true
	// Enum: [Any Single]
	AuthorisationType string `json:"AuthorisationType" yaml:"AuthorisationType"`

	// Date and time at which the requested authorisation flow must be completed.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	CompletionDateTime strfmt.DateTime `json:"CompletionDateTime,omitempty" yaml:"CompletionDateTime,omitempty"`
}

// Validate validates this o b write international standing order consent response7 data authorisation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthorisationType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCompletionDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var oBWriteInternationalStandingOrderConsentResponse7DataAuthorisationTypeAuthorisationTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Any","Single"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalStandingOrderConsentResponse7DataAuthorisationTypeAuthorisationTypePropEnum = append(oBWriteInternationalStandingOrderConsentResponse7DataAuthorisationTypeAuthorisationTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalStandingOrderConsentResponse7DataAuthorisationAuthorisationTypeAny captures enum value "Any"
	OBWriteInternationalStandingOrderConsentResponse7DataAuthorisationAuthorisationTypeAny string = "Any"

	// OBWriteInternationalStandingOrderConsentResponse7DataAuthorisationAuthorisationTypeSingle captures enum value "Single"
	OBWriteInternationalStandingOrderConsentResponse7DataAuthorisationAuthorisationTypeSingle string = "Single"
)

// prop value enum
func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) validateAuthorisationTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalStandingOrderConsentResponse7DataAuthorisationTypeAuthorisationTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) validateAuthorisationType(formats strfmt.Registry) error {

	if err := validate.RequiredString("AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	// value enum
	if err := m.validateAuthorisationTypeEnum("AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) validateCompletionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CompletionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CompletionDateTime", "body", "date-time", m.CompletionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international standing order consent response7 data authorisation based on context it is used
func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalStandingOrderConsentResponse7DataAuthorisation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
