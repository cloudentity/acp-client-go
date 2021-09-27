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

// JWSPayloadSettings j w s payload settings
//
// swagger:model JWSPayloadSettings
type JWSPayloadSettings struct {

	// jwks
	Jwks *ClientJWKs `json:"jwks,omitempty"`

	// URI of the JWKs of the trusted party responsible for signing request body
	JwksURI string `json:"jwks_uri,omitempty"`
}

// Validate validates this j w s payload settings
func (m *JWSPayloadSettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateJwks(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JWSPayloadSettings) validateJwks(formats strfmt.Registry) error {
	if swag.IsZero(m.Jwks) { // not required
		return nil
	}

	if m.Jwks != nil {
		if err := m.Jwks.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this j w s payload settings based on the context it is used
func (m *JWSPayloadSettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateJwks(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *JWSPayloadSettings) contextValidateJwks(ctx context.Context, formats strfmt.Registry) error {

	if m.Jwks != nil {
		if err := m.Jwks.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("jwks")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *JWSPayloadSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *JWSPayloadSettings) UnmarshalBinary(b []byte) error {
	var res JWSPayloadSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
