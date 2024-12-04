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

// RequestValidatedData request validated data
//
// swagger:model RequestValidatedData
type RequestValidatedData struct {

	// anonymous
	Anonymous bool `json:"anonymous,omitempty" yaml:"anonymous,omitempty"`

	// api
	API *API `json:"api,omitempty" yaml:"api,omitempty"`

	// claims
	Claims JwtClaims `json:"claims,omitempty" yaml:"claims,omitempty"`

	// duration ms
	DurationMs int64 `json:"duration_ms,omitempty" yaml:"duration_ms,omitempty"`

	// gateway
	Gateway *Gateway `json:"gateway,omitempty" yaml:"gateway,omitempty"`

	// invalid token
	InvalidToken bool `json:"invalid_token,omitempty" yaml:"invalid_token,omitempty"`

	// output
	Output map[string]string `json:"output,omitempty" yaml:"output,omitempty"`

	// result
	Result *PolicyValidationResult `json:"result,omitempty" yaml:"result,omitempty"`

	// service
	Service *Service `json:"service,omitempty" yaml:"service,omitempty"`
}

// Validate validates this request validated data
func (m *RequestValidatedData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAPI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClaims(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGateway(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResult(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateService(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestValidatedData) validateAPI(formats strfmt.Registry) error {
	if swag.IsZero(m.API) { // not required
		return nil
	}

	if m.API != nil {
		if err := m.API.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("api")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("api")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) validateClaims(formats strfmt.Registry) error {
	if swag.IsZero(m.Claims) { // not required
		return nil
	}

	if m.Claims != nil {
		if err := m.Claims.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("claims")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("claims")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) validateGateway(formats strfmt.Registry) error {
	if swag.IsZero(m.Gateway) { // not required
		return nil
	}

	if m.Gateway != nil {
		if err := m.Gateway.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("gateway")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("gateway")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) validateResult(formats strfmt.Registry) error {
	if swag.IsZero(m.Result) { // not required
		return nil
	}

	if m.Result != nil {
		if err := m.Result.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) validateService(formats strfmt.Registry) error {
	if swag.IsZero(m.Service) { // not required
		return nil
	}

	if m.Service != nil {
		if err := m.Service.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this request validated data based on the context it is used
func (m *RequestValidatedData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAPI(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClaims(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGateway(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateResult(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateService(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RequestValidatedData) contextValidateAPI(ctx context.Context, formats strfmt.Registry) error {

	if m.API != nil {

		if swag.IsZero(m.API) { // not required
			return nil
		}

		if err := m.API.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("api")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("api")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) contextValidateClaims(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Claims) { // not required
		return nil
	}

	if err := m.Claims.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("claims")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("claims")
		}
		return err
	}

	return nil
}

func (m *RequestValidatedData) contextValidateGateway(ctx context.Context, formats strfmt.Registry) error {

	if m.Gateway != nil {

		if swag.IsZero(m.Gateway) { // not required
			return nil
		}

		if err := m.Gateway.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("gateway")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("gateway")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) contextValidateResult(ctx context.Context, formats strfmt.Registry) error {

	if m.Result != nil {

		if swag.IsZero(m.Result) { // not required
			return nil
		}

		if err := m.Result.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("result")
			}
			return err
		}
	}

	return nil
}

func (m *RequestValidatedData) contextValidateService(ctx context.Context, formats strfmt.Registry) error {

	if m.Service != nil {

		if swag.IsZero(m.Service) { // not required
			return nil
		}

		if err := m.Service.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("service")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("service")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RequestValidatedData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RequestValidatedData) UnmarshalBinary(b []byte) error {
	var res RequestValidatedData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
