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

// AttributeConsumingService AttributeConsumingService represents the SAML AttributeConsumingService object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.4.1
//
// swagger:model AttributeConsumingService
type AttributeConsumingService struct {

	// index
	Index int64 `json:"Index,omitempty"`

	// is default
	IsDefault bool `json:"IsDefault,omitempty"`

	// requested attributes
	RequestedAttributes []*RequestedAttribute `json:"RequestedAttributes"`

	// service descriptions
	ServiceDescriptions []*LocalizedName `json:"ServiceDescriptions"`

	// service names
	ServiceNames []*LocalizedName `json:"ServiceNames"`
}

// Validate validates this attribute consuming service
func (m *AttributeConsumingService) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRequestedAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceDescriptions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceNames(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AttributeConsumingService) validateRequestedAttributes(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedAttributes) { // not required
		return nil
	}

	for i := 0; i < len(m.RequestedAttributes); i++ {
		if swag.IsZero(m.RequestedAttributes[i]) { // not required
			continue
		}

		if m.RequestedAttributes[i] != nil {
			if err := m.RequestedAttributes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("RequestedAttributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("RequestedAttributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *AttributeConsumingService) validateServiceDescriptions(formats strfmt.Registry) error {
	if swag.IsZero(m.ServiceDescriptions) { // not required
		return nil
	}

	for i := 0; i < len(m.ServiceDescriptions); i++ {
		if swag.IsZero(m.ServiceDescriptions[i]) { // not required
			continue
		}

		if m.ServiceDescriptions[i] != nil {
			if err := m.ServiceDescriptions[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ServiceDescriptions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ServiceDescriptions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *AttributeConsumingService) validateServiceNames(formats strfmt.Registry) error {
	if swag.IsZero(m.ServiceNames) { // not required
		return nil
	}

	for i := 0; i < len(m.ServiceNames); i++ {
		if swag.IsZero(m.ServiceNames[i]) { // not required
			continue
		}

		if m.ServiceNames[i] != nil {
			if err := m.ServiceNames[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ServiceNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ServiceNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this attribute consuming service based on the context it is used
func (m *AttributeConsumingService) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRequestedAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServiceDescriptions(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateServiceNames(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AttributeConsumingService) contextValidateRequestedAttributes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RequestedAttributes); i++ {

		if m.RequestedAttributes[i] != nil {

			if swag.IsZero(m.RequestedAttributes[i]) { // not required
				return nil
			}

			if err := m.RequestedAttributes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("RequestedAttributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("RequestedAttributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *AttributeConsumingService) contextValidateServiceDescriptions(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ServiceDescriptions); i++ {

		if m.ServiceDescriptions[i] != nil {

			if swag.IsZero(m.ServiceDescriptions[i]) { // not required
				return nil
			}

			if err := m.ServiceDescriptions[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ServiceDescriptions" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ServiceDescriptions" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *AttributeConsumingService) contextValidateServiceNames(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ServiceNames); i++ {

		if m.ServiceNames[i] != nil {

			if swag.IsZero(m.ServiceNames[i]) { // not required
				return nil
			}

			if err := m.ServiceNames[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ServiceNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ServiceNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AttributeConsumingService) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AttributeConsumingService) UnmarshalBinary(b []byte) error {
	var res AttributeConsumingService
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}