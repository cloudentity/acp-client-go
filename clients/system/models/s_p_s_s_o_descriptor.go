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

// SPSSODescriptor SPSSODescriptor represents the SAML SPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.2
//
// swagger:model SPSSODescriptor
type SPSSODescriptor struct {

	// artifact resolution services
	ArtifactResolutionServices []*IndexedEndpoint `json:"ArtifactResolutionServices" yaml:"ArtifactResolutionServices"`

	// assertion consumer services
	AssertionConsumerServices []*IndexedEndpoint `json:"AssertionConsumerServices" yaml:"AssertionConsumerServices"`

	// attribute consuming services
	AttributeConsumingServices []*AttributeConsumingService `json:"AttributeConsumingServices" yaml:"AttributeConsumingServices"`

	// authn requests signed
	AuthnRequestsSigned bool `json:"AuthnRequestsSigned,omitempty" yaml:"AuthnRequestsSigned,omitempty"`

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

	// manage name ID services
	ManageNameIDServices []*Endpoint `json:"ManageNameIDServices" yaml:"ManageNameIDServices"`

	// name ID formats
	NameIDFormats []NameIDFormat `json:"NameIDFormats" yaml:"NameIDFormats"`

	// organization
	Organization *Organization `json:"Organization,omitempty" yaml:"Organization,omitempty"`

	// protocol support enumeration
	ProtocolSupportEnumeration string `json:"ProtocolSupportEnumeration,omitempty" yaml:"ProtocolSupportEnumeration,omitempty"`

	// signature
	Signature *Element `json:"Signature,omitempty" yaml:"Signature,omitempty"`

	// single logout services
	SingleLogoutServices []*Endpoint `json:"SingleLogoutServices" yaml:"SingleLogoutServices"`

	// valid until
	// Format: date-time
	ValidUntil strfmt.DateTime `json:"ValidUntil,omitempty" yaml:"ValidUntil,omitempty"`

	// want assertions signed
	WantAssertionsSigned bool `json:"WantAssertionsSigned,omitempty" yaml:"WantAssertionsSigned,omitempty"`

	// XML name
	XMLName *Name `json:"XMLName,omitempty" yaml:"XMLName,omitempty"`
}

// Validate validates this s p s s o descriptor
func (m *SPSSODescriptor) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateArtifactResolutionServices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAssertionConsumerServices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAttributeConsumingServices(formats); err != nil {
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

	if err := m.validateManageNameIDServices(formats); err != nil {
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

	if err := m.validateSingleLogoutServices(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateValidUntil(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateXMLName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SPSSODescriptor) validateArtifactResolutionServices(formats strfmt.Registry) error {
	if swag.IsZero(m.ArtifactResolutionServices) { // not required
		return nil
	}

	for i := 0; i < len(m.ArtifactResolutionServices); i++ {
		if swag.IsZero(m.ArtifactResolutionServices[i]) { // not required
			continue
		}

		if m.ArtifactResolutionServices[i] != nil {
			if err := m.ArtifactResolutionServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ArtifactResolutionServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ArtifactResolutionServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) validateAssertionConsumerServices(formats strfmt.Registry) error {
	if swag.IsZero(m.AssertionConsumerServices) { // not required
		return nil
	}

	for i := 0; i < len(m.AssertionConsumerServices); i++ {
		if swag.IsZero(m.AssertionConsumerServices[i]) { // not required
			continue
		}

		if m.AssertionConsumerServices[i] != nil {
			if err := m.AssertionConsumerServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AssertionConsumerServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AssertionConsumerServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) validateAttributeConsumingServices(formats strfmt.Registry) error {
	if swag.IsZero(m.AttributeConsumingServices) { // not required
		return nil
	}

	for i := 0; i < len(m.AttributeConsumingServices); i++ {
		if swag.IsZero(m.AttributeConsumingServices[i]) { // not required
			continue
		}

		if m.AttributeConsumingServices[i] != nil {
			if err := m.AttributeConsumingServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AttributeConsumingServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AttributeConsumingServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) validateCacheDuration(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateContactPeople(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateKeyDescriptors(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateManageNameIDServices(formats strfmt.Registry) error {
	if swag.IsZero(m.ManageNameIDServices) { // not required
		return nil
	}

	for i := 0; i < len(m.ManageNameIDServices); i++ {
		if swag.IsZero(m.ManageNameIDServices[i]) { // not required
			continue
		}

		if m.ManageNameIDServices[i] != nil {
			if err := m.ManageNameIDServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ManageNameIDServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ManageNameIDServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) validateNameIDFormats(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateOrganization(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateSignature(formats strfmt.Registry) error {
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

func (m *SPSSODescriptor) validateSingleLogoutServices(formats strfmt.Registry) error {
	if swag.IsZero(m.SingleLogoutServices) { // not required
		return nil
	}

	for i := 0; i < len(m.SingleLogoutServices); i++ {
		if swag.IsZero(m.SingleLogoutServices[i]) { // not required
			continue
		}

		if m.SingleLogoutServices[i] != nil {
			if err := m.SingleLogoutServices[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("SingleLogoutServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("SingleLogoutServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) validateValidUntil(formats strfmt.Registry) error {
	if swag.IsZero(m.ValidUntil) { // not required
		return nil
	}

	if err := validate.FormatOf("ValidUntil", "body", "date-time", m.ValidUntil.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SPSSODescriptor) validateXMLName(formats strfmt.Registry) error {
	if swag.IsZero(m.XMLName) { // not required
		return nil
	}

	if m.XMLName != nil {
		if err := m.XMLName.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("XMLName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("XMLName")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this s p s s o descriptor based on the context it is used
func (m *SPSSODescriptor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateArtifactResolutionServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAssertionConsumerServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAttributeConsumingServices(ctx, formats); err != nil {
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

	if err := m.contextValidateManageNameIDServices(ctx, formats); err != nil {
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

	if err := m.contextValidateSingleLogoutServices(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateXMLName(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SPSSODescriptor) contextValidateArtifactResolutionServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ArtifactResolutionServices); i++ {

		if m.ArtifactResolutionServices[i] != nil {

			if swag.IsZero(m.ArtifactResolutionServices[i]) { // not required
				return nil
			}

			if err := m.ArtifactResolutionServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ArtifactResolutionServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ArtifactResolutionServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) contextValidateAssertionConsumerServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AssertionConsumerServices); i++ {

		if m.AssertionConsumerServices[i] != nil {

			if swag.IsZero(m.AssertionConsumerServices[i]) { // not required
				return nil
			}

			if err := m.AssertionConsumerServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AssertionConsumerServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AssertionConsumerServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) contextValidateAttributeConsumingServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AttributeConsumingServices); i++ {

		if m.AttributeConsumingServices[i] != nil {

			if swag.IsZero(m.AttributeConsumingServices[i]) { // not required
				return nil
			}

			if err := m.AttributeConsumingServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("AttributeConsumingServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("AttributeConsumingServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) contextValidateCacheDuration(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateContactPeople(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateKeyDescriptors(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateManageNameIDServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ManageNameIDServices); i++ {

		if m.ManageNameIDServices[i] != nil {

			if swag.IsZero(m.ManageNameIDServices[i]) { // not required
				return nil
			}

			if err := m.ManageNameIDServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ManageNameIDServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("ManageNameIDServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) contextValidateNameIDFormats(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateOrganization(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateSignature(ctx context.Context, formats strfmt.Registry) error {

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

func (m *SPSSODescriptor) contextValidateSingleLogoutServices(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SingleLogoutServices); i++ {

		if m.SingleLogoutServices[i] != nil {

			if swag.IsZero(m.SingleLogoutServices[i]) { // not required
				return nil
			}

			if err := m.SingleLogoutServices[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("SingleLogoutServices" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("SingleLogoutServices" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SPSSODescriptor) contextValidateXMLName(ctx context.Context, formats strfmt.Registry) error {

	if m.XMLName != nil {

		if swag.IsZero(m.XMLName) { // not required
			return nil
		}

		if err := m.XMLName.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("XMLName")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("XMLName")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SPSSODescriptor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SPSSODescriptor) UnmarshalBinary(b []byte) error {
	var res SPSSODescriptor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
