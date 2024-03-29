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

// UserOrganizationsResponse user organizations response
//
// swagger:model UserOrganizationsResponse
type UserOrganizationsResponse struct {

	// cursor
	Cursor Cursor `json:"cursor,omitempty" yaml:"cursor,omitempty"`

	// organizations
	Organizations []*OrganizationResponse `json:"organizations" yaml:"organizations"`
}

// Validate validates this user organizations response
func (m *UserOrganizationsResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCursor(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizations(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserOrganizationsResponse) validateCursor(formats strfmt.Registry) error {
	if swag.IsZero(m.Cursor) { // not required
		return nil
	}

	if err := m.Cursor.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("cursor")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("cursor")
		}
		return err
	}

	return nil
}

func (m *UserOrganizationsResponse) validateOrganizations(formats strfmt.Registry) error {
	if swag.IsZero(m.Organizations) { // not required
		return nil
	}

	for i := 0; i < len(m.Organizations); i++ {
		if swag.IsZero(m.Organizations[i]) { // not required
			continue
		}

		if m.Organizations[i] != nil {
			if err := m.Organizations[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("organizations" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("organizations" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this user organizations response based on the context it is used
func (m *UserOrganizationsResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCursor(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganizations(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserOrganizationsResponse) contextValidateCursor(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Cursor) { // not required
		return nil
	}

	if err := m.Cursor.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("cursor")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("cursor")
		}
		return err
	}

	return nil
}

func (m *UserOrganizationsResponse) contextValidateOrganizations(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Organizations); i++ {

		if m.Organizations[i] != nil {

			if swag.IsZero(m.Organizations[i]) { // not required
				return nil
			}

			if err := m.Organizations[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("organizations" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("organizations" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserOrganizationsResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserOrganizationsResponse) UnmarshalBinary(b []byte) error {
	var res UserOrganizationsResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
