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

// APIGroupMetadata API group metadata
//
// swagger:model APIGroupMetadata
type APIGroupMetadata struct {

	// apigee
	Apigee *ApigeeMetadata `json:"apigee,omitempty" yaml:"apigee,omitempty"`

	// aws
	Aws *AWSMetadata `json:"aws,omitempty" yaml:"aws,omitempty"`

	// azure
	Azure *AzureMetadata `json:"azure,omitempty" yaml:"azure,omitempty"`

	// Gateway type
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this API group metadata
func (m *APIGroupMetadata) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateApigee(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAws(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAzure(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIGroupMetadata) validateApigee(formats strfmt.Registry) error {
	if swag.IsZero(m.Apigee) { // not required
		return nil
	}

	if m.Apigee != nil {
		if err := m.Apigee.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("apigee")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("apigee")
			}
			return err
		}
	}

	return nil
}

func (m *APIGroupMetadata) validateAws(formats strfmt.Registry) error {
	if swag.IsZero(m.Aws) { // not required
		return nil
	}

	if m.Aws != nil {
		if err := m.Aws.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("aws")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("aws")
			}
			return err
		}
	}

	return nil
}

func (m *APIGroupMetadata) validateAzure(formats strfmt.Registry) error {
	if swag.IsZero(m.Azure) { // not required
		return nil
	}

	if m.Azure != nil {
		if err := m.Azure.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this API group metadata based on the context it is used
func (m *APIGroupMetadata) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateApigee(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAws(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAzure(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *APIGroupMetadata) contextValidateApigee(ctx context.Context, formats strfmt.Registry) error {

	if m.Apigee != nil {

		if swag.IsZero(m.Apigee) { // not required
			return nil
		}

		if err := m.Apigee.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("apigee")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("apigee")
			}
			return err
		}
	}

	return nil
}

func (m *APIGroupMetadata) contextValidateAws(ctx context.Context, formats strfmt.Registry) error {

	if m.Aws != nil {

		if swag.IsZero(m.Aws) { // not required
			return nil
		}

		if err := m.Aws.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("aws")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("aws")
			}
			return err
		}
	}

	return nil
}

func (m *APIGroupMetadata) contextValidateAzure(ctx context.Context, formats strfmt.Registry) error {

	if m.Azure != nil {

		if swag.IsZero(m.Azure) { // not required
			return nil
		}

		if err := m.Azure.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("azure")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("azure")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *APIGroupMetadata) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIGroupMetadata) UnmarshalBinary(b []byte) error {
	var res APIGroupMetadata
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
