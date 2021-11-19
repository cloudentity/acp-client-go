// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// Error Error
//
// swagger:model Error
type Error struct {

	// Cdigo de erro especfico do endpoint
	// Required: true
	// Max Length: 255
	// Pattern: [\w\W\s]*
	Code string `json:"code"`

	// Descrio legvel por humanos deste erro especfico
	// Required: true
	// Max Length: 2048
	// Pattern: [\w\W\s]*
	Detail string `json:"detail"`

	// Ttulo legvel por humanos deste erro especfico
	// Required: true
	// Max Length: 255
	// Pattern: [\w\W\s]*
	Title string `json:"title"`
}

// Validate validates this error
func (m *Error) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDetail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTitle(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Error) validateCode(formats strfmt.Registry) error {

	if err := validate.RequiredString("code", "body", m.Code); err != nil {
		return err
	}

	if err := validate.MaxLength("code", "body", m.Code, 255); err != nil {
		return err
	}

	if err := validate.Pattern("code", "body", m.Code, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

func (m *Error) validateDetail(formats strfmt.Registry) error {

	if err := validate.RequiredString("detail", "body", m.Detail); err != nil {
		return err
	}

	if err := validate.MaxLength("detail", "body", m.Detail, 2048); err != nil {
		return err
	}

	if err := validate.Pattern("detail", "body", m.Detail, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

func (m *Error) validateTitle(formats strfmt.Registry) error {

	if err := validate.RequiredString("title", "body", m.Title); err != nil {
		return err
	}

	if err := validate.MaxLength("title", "body", m.Title, 255); err != nil {
		return err
	}

	if err := validate.Pattern("title", "body", m.Title, `[\w\W\s]*`); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this error based on context it is used
func (m *Error) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Error) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Error) UnmarshalBinary(b []byte) error {
	var res Error
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}