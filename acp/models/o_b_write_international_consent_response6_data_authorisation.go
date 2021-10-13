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

// OBWriteInternationalConsentResponse6DataAuthorisation OBWriteInternationalConsentResponse6DataAuthorisation The authorisation type request from the TPP.
//
// swagger:model OBWriteInternationalConsentResponse6DataAuthorisation
type OBWriteInternationalConsentResponse6DataAuthorisation struct {

	// Type of authorisation flow requested.
	// Required: true
	// Enum: [Any Single]
	AuthorisationType string `json:"AuthorisationType"`

	// Date and time at which the requested authorisation flow must be completed.All dates in the JSON payloads are represented in ISO 8601 date-time format.
	// All date-time fields in responses must include the timezone. An example is below:
	// 2017-04-05T10:43:07+00:00
	// Format: date-time
	// Format: date-time
	CompletionDateTime strfmt.DateTime `json:"CompletionDateTime,omitempty"`
}

// Validate validates this o b write international consent response6 data authorisation
func (m *OBWriteInternationalConsentResponse6DataAuthorisation) Validate(formats strfmt.Registry) error {
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

var oBWriteInternationalConsentResponse6DataAuthorisationTypeAuthorisationTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["Any","Single"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		oBWriteInternationalConsentResponse6DataAuthorisationTypeAuthorisationTypePropEnum = append(oBWriteInternationalConsentResponse6DataAuthorisationTypeAuthorisationTypePropEnum, v)
	}
}

const (

	// OBWriteInternationalConsentResponse6DataAuthorisationAuthorisationTypeAny captures enum value "Any"
	OBWriteInternationalConsentResponse6DataAuthorisationAuthorisationTypeAny string = "Any"

	// OBWriteInternationalConsentResponse6DataAuthorisationAuthorisationTypeSingle captures enum value "Single"
	OBWriteInternationalConsentResponse6DataAuthorisationAuthorisationTypeSingle string = "Single"
)

// prop value enum
func (m *OBWriteInternationalConsentResponse6DataAuthorisation) validateAuthorisationTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, oBWriteInternationalConsentResponse6DataAuthorisationTypeAuthorisationTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *OBWriteInternationalConsentResponse6DataAuthorisation) validateAuthorisationType(formats strfmt.Registry) error {

	if err := validate.RequiredString("AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	// value enum
	if err := m.validateAuthorisationTypeEnum("AuthorisationType", "body", m.AuthorisationType); err != nil {
		return err
	}

	return nil
}

func (m *OBWriteInternationalConsentResponse6DataAuthorisation) validateCompletionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CompletionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CompletionDateTime", "body", "date-time", m.CompletionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this o b write international consent response6 data authorisation based on context it is used
func (m *OBWriteInternationalConsentResponse6DataAuthorisation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OBWriteInternationalConsentResponse6DataAuthorisation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OBWriteInternationalConsentResponse6DataAuthorisation) UnmarshalBinary(b []byte) error {
	var res OBWriteInternationalConsentResponse6DataAuthorisation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}