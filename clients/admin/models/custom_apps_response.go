// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CustomAppsResponse CustomApps
//
// swagger:model CustomAppsResponse
type CustomAppsResponse struct {

	// list of CustomApps
	// in:body
	CustomApps []*CustomApp `json:"custom_apps" yaml:"custom_apps"`

	// The ETag HTTP header is an identifier for a specific version of a resource
	//
	// in:header
	Etag string `json:"etag,omitempty" yaml:"etag,omitempty"`
}

// Validate validates this custom apps response
func (m *CustomAppsResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCustomApps(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CustomAppsResponse) validateCustomApps(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomApps) { // not required
		return nil
	}

	for i := 0; i < len(m.CustomApps); i++ {
		if swag.IsZero(m.CustomApps[i]) { // not required
			continue
		}

		if m.CustomApps[i] != nil {
			if err := m.CustomApps[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("custom_apps" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("custom_apps" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this custom apps response based on the context it is used
func (m *CustomAppsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCustomApps(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CustomAppsResponse) contextValidateCustomApps(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.CustomApps); i++ {

		if m.CustomApps[i] != nil {

			if swag.IsZero(m.CustomApps[i]) { // not required
				return nil
			}

			if err := m.CustomApps[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("custom_apps" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("custom_apps" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *CustomAppsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CustomAppsResponse) UnmarshalBinary(b []byte) error {
	var res CustomAppsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
