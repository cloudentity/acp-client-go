// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RequestValidatedPayload request validated payload
//
// swagger:model RequestValidatedPayload
type RequestValidatedPayload struct {

	// access request data
	AccessRequestData *AccessRequestData `json:"access_request_data,omitempty" yaml:"access_request_data,omitempty"`

	// request validated data
	RequestValidatedData *RequestValidatedData `json:"request_validated_data,omitempty" yaml:"request_validated_data,omitempty"`
}

// Validate validates this request validated payload
func (m *RequestValidatedPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessRequestData(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestValidatedData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestValidatedPayload) validateAccessRequestData(formats strfmt.Registry) error {
	if swag.IsZero(m.AccessRequestData) { // not required
		return nil
	}

	if m.AccessRequestData != nil {
		if err := m.AccessRequestData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("access_request_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("access_request_data")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) validateRequestValidatedData(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestValidatedData) { // not required
		return nil
	}

	if m.RequestValidatedData != nil {
		if err := m.RequestValidatedData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("request_validated_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("request_validated_data")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this request validated payload based on the context it is used
func (m *RequestValidatedPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccessRequestData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestValidatedData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestValidatedPayload) contextValidateAccessRequestData(ctx context.Context, formats strfmt.Registry) error {

	if m.AccessRequestData != nil {

		if swag.IsZero(m.AccessRequestData) { // not required
			return nil
		}

		if err := m.AccessRequestData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("access_request_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("access_request_data")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedPayload) contextValidateRequestValidatedData(ctx context.Context, formats strfmt.Registry) error {

	if m.RequestValidatedData != nil {

		if swag.IsZero(m.RequestValidatedData) { // not required
			return nil
		}

		if err := m.RequestValidatedData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("request_validated_data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("request_validated_data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestValidatedPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestValidatedPayload) UnmarshalBinary(b []byte) error {
	var res RequestValidatedPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
