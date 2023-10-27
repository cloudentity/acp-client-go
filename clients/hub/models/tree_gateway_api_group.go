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

// TreeGatewayAPIGroup tree gateway API group
//
// swagger:model TreeGatewayAPIGroup
type TreeGatewayAPIGroup struct {

	// List of APIs
	Apis []*GatewayAPI `json:"apis"`

	// metadata
	Metadata *APIGroupMetadata `json:"metadata,omitempty"`

	// API group name
	Name string `json:"name,omitempty"`

	// service id
	ServiceID string `json:"service_id,omitempty"`
}

// Validate validates this tree gateway API group
func (m *TreeGatewayAPIGroup) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApis(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeGatewayAPIGroup) validateApis(formats strfmt.Registry) error {
	if swag.IsZero(m.Apis) { // not required
		return nil
	}

	for i := 0; i < len(m.Apis); i++ {
		if swag.IsZero(m.Apis[i]) { // not required
			continue
		}

		if m.Apis[i] != nil {
			if err := m.Apis[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TreeGatewayAPIGroup) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this tree gateway API group based on the context it is used
func (m *TreeGatewayAPIGroup) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApis(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TreeGatewayAPIGroup) contextValidateApis(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Apis); i++ {

		if m.Apis[i] != nil {

			if swag.IsZero(m.Apis[i]) { // not required
				return nil
			}

			if err := m.Apis[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apis" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apis" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *TreeGatewayAPIGroup) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.Metadata != nil {

		if swag.IsZero(m.Metadata) { // not required
			return nil
		}

		if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TreeGatewayAPIGroup) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TreeGatewayAPIGroup) UnmarshalBinary(b []byte) error {
	var res TreeGatewayAPIGroup
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
