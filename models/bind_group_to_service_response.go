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

// BindGroupToServiceResponse bind group to service response
//
// swagger:model BindGroupToServiceResponse
type BindGroupToServiceResponse struct {

	// not removed policies
	NotRemovedPolicies []*Policy `json:"not_removed_policies"`

	// removed apis
	RemovedApis []*API `json:"removed_apis"`

	// removed policies
	RemovedPolicies []*Policy `json:"removed_policies"`
}

// Validate validates this bind group to service response
func (m *BindGroupToServiceResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateNotRemovedPolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRemovedApis(formats); err != nil {
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

func (m *BindGroupToServiceResponse) validateNotRemovedPolicies(formats strfmt.Registry) error {
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

func (m *BindGroupToServiceResponse) validateRemovedApis(formats strfmt.Registry) error {
	if swag.IsZero(m.RemovedApis) { // not required
		return nil
	}

	for i := 0; i < len(m.RemovedApis); i++ {
		if swag.IsZero(m.RemovedApis[i]) { // not required
			continue
		}

		if m.RemovedApis[i] != nil {
			if err := m.RemovedApis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *BindGroupToServiceResponse) validateRemovedPolicies(formats strfmt.Registry) error {
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

// ContextValidate validate this bind group to service response based on the context it is used
func (m *BindGroupToServiceResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateNotRemovedPolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRemovedApis(ctx, formats); err != nil {
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

func (m *BindGroupToServiceResponse) contextValidateNotRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

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

func (m *BindGroupToServiceResponse) contextValidateRemovedApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RemovedApis); i++ {

		if m.RemovedApis[i] != nil {
			if err := m.RemovedApis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("removed_apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *BindGroupToServiceResponse) contextValidateRemovedPolicies(ctx context.Context, formats strfmt.Registry) error {

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
func (m *BindGroupToServiceResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BindGroupToServiceResponse) UnmarshalBinary(b []byte) error {
	var res BindGroupToServiceResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
