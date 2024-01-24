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
	"github.com/go-openapi/validate"
)

// RoleDescriptor RoleDescriptor represents the SAML element RoleDescriptor.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.1
//
// swagger:model RoleDescriptor
type RoleDescriptor struct {

	// cache duration
	CacheDuration Duration `json:"CacheDuration,omitempty" yaml:"CacheDuration,omitempty"`

	// contact people
	ContactPeople []*ContactPerson `json:"ContactPeople" yaml:"ContactPeople"`

	// error URL
	ErrorURL string `json:"ErrorURL,omitempty" yaml:"ErrorURL,omitempty"`

	// ID
	ID string `json:"ID,omitempty" yaml:"ID,omitempty"`

	// key descriptors
	KeyDescriptors []*KeyDescriptor `json:"KeyDescriptors" yaml:"KeyDescriptors"`

	// organization
	Organization *Organization `json:"Organization,omitempty" yaml:"Organization,omitempty"`

	// protocol support enumeration
	ProtocolSupportEnumeration string `json:"ProtocolSupportEnumeration,omitempty" yaml:"ProtocolSupportEnumeration,omitempty"`

	// signature
	Signature *Element `json:"Signature,omitempty" yaml:"Signature,omitempty"`

	// valid until
	// Format: date-time
	ValidUntil strfmt.DateTime `json:"ValidUntil,omitempty" yaml:"ValidUntil,omitempty"`
}

// Validate validates this role descriptor
func (m *RoleDescriptor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCacheDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContactPeople(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeyDescriptors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganization(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSignature(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValidUntil(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RoleDescriptor) validateCacheDuration(formats strfmt.Registry) error {
	if swag.IsZero(m.CacheDuration) { // not required
		return nil
	}

	if err := m.CacheDuration.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("CacheDuration")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("CacheDuration")
		}
		return err
	}

	return nil
}

func (m *RoleDescriptor) validateContactPeople(formats strfmt.Registry) error {
	if swag.IsZero(m.ContactPeople) { // not required
		return nil
	}

	for i := 0; i < len(m.ContactPeople); i++ {
		if swag.IsZero(m.ContactPeople[i]) { // not required
			continue
		}

		if m.ContactPeople[i] != nil {
			if err := m.ContactPeople[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ContactPeople" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ContactPeople" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RoleDescriptor) validateKeyDescriptors(formats strfmt.Registry) error {
	if swag.IsZero(m.KeyDescriptors) { // not required
		return nil
	}

	for i := 0; i < len(m.KeyDescriptors); i++ {
		if swag.IsZero(m.KeyDescriptors[i]) { // not required
			continue
		}

		if m.KeyDescriptors[i] != nil {
			if err := m.KeyDescriptors[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("KeyDescriptors" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("KeyDescriptors" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RoleDescriptor) validateOrganization(formats strfmt.Registry) error {
	if swag.IsZero(m.Organization) { // not required
		return nil
	}

	if m.Organization != nil {
		if err := m.Organization.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Organization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Organization")
			}
			return err
		}
	}

	return nil
}

func (m *RoleDescriptor) validateSignature(formats strfmt.Registry) error {
	if swag.IsZero(m.Signature) { // not required
		return nil
	}

	if m.Signature != nil {
		if err := m.Signature.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Signature")
			}
			return err
		}
	}

	return nil
}

func (m *RoleDescriptor) validateValidUntil(formats strfmt.Registry) error {
	if swag.IsZero(m.ValidUntil) { // not required
		return nil
	}

	if err := validate.FormatOf("ValidUntil", "body", "date-time", m.ValidUntil.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this role descriptor based on the context it is used
func (m *RoleDescriptor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCacheDuration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateContactPeople(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateKeyDescriptors(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganization(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSignature(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RoleDescriptor) contextValidateCacheDuration(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.CacheDuration) { // not required
		return nil
	}

	if err := m.CacheDuration.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("CacheDuration")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("CacheDuration")
		}
		return err
	}

	return nil
}

func (m *RoleDescriptor) contextValidateContactPeople(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ContactPeople); i++ {

		if m.ContactPeople[i] != nil {

			if swag.IsZero(m.ContactPeople[i]) { // not required
				return nil
			}

			if err := m.ContactPeople[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ContactPeople" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ContactPeople" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RoleDescriptor) contextValidateKeyDescriptors(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.KeyDescriptors); i++ {

		if m.KeyDescriptors[i] != nil {

			if swag.IsZero(m.KeyDescriptors[i]) { // not required
				return nil
			}

			if err := m.KeyDescriptors[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("KeyDescriptors" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("KeyDescriptors" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *RoleDescriptor) contextValidateOrganization(ctx context.Context, formats strfmt.Registry) error {

	if m.Organization != nil {

		if swag.IsZero(m.Organization) { // not required
			return nil
		}

		if err := m.Organization.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Organization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Organization")
			}
			return err
		}
	}

	return nil
}

func (m *RoleDescriptor) contextValidateSignature(ctx context.Context, formats strfmt.Registry) error {

	if m.Signature != nil {

		if swag.IsZero(m.Signature) { // not required
			return nil
		}

		if err := m.Signature.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Signature")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Signature")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RoleDescriptor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RoleDescriptor) UnmarshalBinary(b []byte) error {
	var res RoleDescriptor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
