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

// PDPDescriptor PDPDescriptor represents the SAML PDPDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.6
//
// swagger:model PDPDescriptor
type PDPDescriptor struct {

	// assertion ID request services
	AssertionIDRequestServices []*Endpoint `json:"AssertionIDRequestServices" yaml:"AssertionIDRequestServices"`

	// authz services
	AuthzServices []*Endpoint `json:"AuthzServices" yaml:"AuthzServices"`

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

	// name ID formats
	NameIDFormats []NameIDFormat `json:"NameIDFormats" yaml:"NameIDFormats"`

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

// Validate validates this p d p descriptor
func (m *PDPDescriptor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAssertionIDRequestServices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthzServices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCacheDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContactPeople(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateKeyDescriptors(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNameIDFormats(formats); err != nil {
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

func (m *PDPDescriptor) validateAssertionIDRequestServices(formats strfmt.Registry) error {
	if swag.IsZero(m.AssertionIDRequestServices) { // not required
		return nil
	}

	for i := 0; i < len(m.AssertionIDRequestServices); i++ {
		if swag.IsZero(m.AssertionIDRequestServices[i]) { // not required
			continue
		}

		if m.AssertionIDRequestServices[i] != nil {
			if err := m.AssertionIDRequestServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AssertionIDRequestServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AssertionIDRequestServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PDPDescriptor) validateAuthzServices(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthzServices) { // not required
		return nil
	}

	for i := 0; i < len(m.AuthzServices); i++ {
		if swag.IsZero(m.AuthzServices[i]) { // not required
			continue
		}

		if m.AuthzServices[i] != nil {
			if err := m.AuthzServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AuthzServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AuthzServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PDPDescriptor) validateCacheDuration(formats strfmt.Registry) error {
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

func (m *PDPDescriptor) validateContactPeople(formats strfmt.Registry) error {
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

func (m *PDPDescriptor) validateKeyDescriptors(formats strfmt.Registry) error {
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

func (m *PDPDescriptor) validateNameIDFormats(formats strfmt.Registry) error {
	if swag.IsZero(m.NameIDFormats) { // not required
		return nil
	}

	for i := 0; i < len(m.NameIDFormats); i++ {

		if err := m.NameIDFormats[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("NameIDFormats" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("NameIDFormats" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *PDPDescriptor) validateOrganization(formats strfmt.Registry) error {
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

func (m *PDPDescriptor) validateSignature(formats strfmt.Registry) error {
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

func (m *PDPDescriptor) validateValidUntil(formats strfmt.Registry) error {
	if swag.IsZero(m.ValidUntil) { // not required
		return nil
	}

	if err := validate.FormatOf("ValidUntil", "body", "date-time", m.ValidUntil.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this p d p descriptor based on the context it is used
func (m *PDPDescriptor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAssertionIDRequestServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAuthzServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCacheDuration(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateContactPeople(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateKeyDescriptors(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNameIDFormats(ctx, formats); err != nil {
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

func (m *PDPDescriptor) contextValidateAssertionIDRequestServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AssertionIDRequestServices); i++ {

		if m.AssertionIDRequestServices[i] != nil {

			if swag.IsZero(m.AssertionIDRequestServices[i]) { // not required
				return nil
			}

			if err := m.AssertionIDRequestServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AssertionIDRequestServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AssertionIDRequestServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PDPDescriptor) contextValidateAuthzServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AuthzServices); i++ {

		if m.AuthzServices[i] != nil {

			if swag.IsZero(m.AuthzServices[i]) { // not required
				return nil
			}

			if err := m.AuthzServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AuthzServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AuthzServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PDPDescriptor) contextValidateCacheDuration(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PDPDescriptor) contextValidateContactPeople(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PDPDescriptor) contextValidateKeyDescriptors(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PDPDescriptor) contextValidateNameIDFormats(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.NameIDFormats); i++ {

		if swag.IsZero(m.NameIDFormats[i]) { // not required
			return nil
		}

		if err := m.NameIDFormats[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("NameIDFormats" + "." + strconv.Itoa(i))
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("NameIDFormats" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

func (m *PDPDescriptor) contextValidateOrganization(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PDPDescriptor) contextValidateSignature(ctx context.Context, formats strfmt.Registry) error {

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
func (m *PDPDescriptor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PDPDescriptor) UnmarshalBinary(b []byte) error {
	var res PDPDescriptor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
