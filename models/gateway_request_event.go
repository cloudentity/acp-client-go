// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GatewayRequestEvent gateway request event
//
// swagger:model GatewayRequestEvent
type GatewayRequestEvent struct {

	// API ID
	APIID string `json:"api_id,omitempty"`

	// forwarded for
	ForwardedFor string `json:"x_forwarded_for,omitempty"`

	// real IP
	RealIP string `json:"x_real_ip,omitempty"`

	// token
	Token string `json:"token,omitempty"`

	// user agent
	UserAgent string `json:"user_agent,omitempty"`

	// result
	Result *PolicyValidationResult `json:"result,omitempty"`
}

// Validate validates this gateway request event
func (m *GatewayRequestEvent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateResult(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GatewayRequestEvent) validateResult(formats strfmt.Registry) error {

	if swag.IsZero(m.Result) { // not required
		return nil
	}

	if m.Result != nil {
		if err := m.Result.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("result")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GatewayRequestEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GatewayRequestEvent) UnmarshalBinary(b []byte) error {
	var res GatewayRequestEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
