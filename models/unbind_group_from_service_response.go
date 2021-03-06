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

// UnbindGroupFromServiceResponse unbind group from service response
//
// swagger:model UnbindGroupFromServiceResponse
type UnbindGroupFromServiceResponse struct {

	// not removed policies
	NotRemovedPolicies []*Policy `json:"not_removed_policies"`

	// removed a p is
	RemovedAPIs []*API `json:"removed_apis"`

	// removed policies
	RemovedPolicies []*Policy `json:"removed_policies"`
}

// Validate validates this unbind group from service response
func (m *UnbindGroupFromServiceResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNotRemovedPolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemovedAPIs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemovedPolicies(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UnbindGroupFromServiceResponse) validateNotRemovedPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.NotRemovedPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.NotRemovedPolicies); i++ {
		if swag.IsZero(m.NotRemovedPolicies[i]) { // not required
			continue
		}

		if m.NotRemovedPolicies[i] != nil {
			if err := m.NotRemovedPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UnbindGroupFromServiceResponse) validateRemovedAPIs(formats strfmt.Registry) error {
	if swag.IsZero(m.RemovedAPIs) { // not required
		return nil
	}

	for i := 0; i < len(m.RemovedAPIs); i++ {
		if swag.IsZero(m.RemovedAPIs[i]) { // not required
			continue
		}

		if m.RemovedAPIs[i] != nil {
			if err := m.RemovedAPIs[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UnbindGroupFromServiceResponse) validateRemovedPolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.RemovedPolicies) { // not required
		return nil
	}

	for i := 0; i < len(m.RemovedPolicies); i++ {
		if swag.IsZero(m.RemovedPolicies[i]) { // not required
			continue
		}

		if m.RemovedPolicies[i] != nil {
			if err := m.RemovedPolicies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this unbind group from service response based on the context it is used
func (m *UnbindGroupFromServiceResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateNotRemovedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemovedAPIs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemovedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UnbindGroupFromServiceResponse) contextValidateNotRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NotRemovedPolicies); i++ {

		if m.NotRemovedPolicies[i] != nil {
			if err := m.NotRemovedPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("not_removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UnbindGroupFromServiceResponse) contextValidateRemovedAPIs(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RemovedAPIs); i++ {

		if m.RemovedAPIs[i] != nil {
			if err := m.RemovedAPIs[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UnbindGroupFromServiceResponse) contextValidateRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RemovedPolicies); i++ {

		if m.RemovedPolicies[i] != nil {
			if err := m.RemovedPolicies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *UnbindGroupFromServiceResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UnbindGroupFromServiceResponse) UnmarshalBinary(b []byte) error {
	var res UnbindGroupFromServiceResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
