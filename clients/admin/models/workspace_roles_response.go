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

// WorkspaceRolesResponse workspace roles response
//
// swagger:model WorkspaceRolesResponse
type WorkspaceRolesResponse struct {

	// subjects
	Subjects []*WorkspaceRoleSubject `json:"subjects" yaml:"subjects"`
}

// Validate validates this workspace roles response
func (m *WorkspaceRolesResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSubjects(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WorkspaceRolesResponse) validateSubjects(formats strfmt.Registry) error {
	if swag.IsZero(m.Subjects) { // not required
		return nil
	}

	for i := 0; i < len(m.Subjects); i++ {
		if swag.IsZero(m.Subjects[i]) { // not required
			continue
		}

		if m.Subjects[i] != nil {
			if err := m.Subjects[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("subjects" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("subjects" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this workspace roles response based on the context it is used
func (m *WorkspaceRolesResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateSubjects(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WorkspaceRolesResponse) contextValidateSubjects(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Subjects); i++ {

		if m.Subjects[i] != nil {

			if swag.IsZero(m.Subjects[i]) { // not required
				return nil
			}

			if err := m.Subjects[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("subjects" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("subjects" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *WorkspaceRolesResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WorkspaceRolesResponse) UnmarshalBinary(b []byte) error {
	var res WorkspaceRolesResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
