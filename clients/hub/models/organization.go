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

// Organization Organization represents the SAML Organization object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.1
//
// swagger:model Organization
type Organization struct {

	// organization display names
	OrganizationDisplayNames []*LocalizedName `json:"OrganizationDisplayNames"`

	// organization names
	OrganizationNames []*LocalizedName `json:"OrganizationNames"`

	// organization u r ls
	OrganizationURLs []*LocalizedURI `json:"OrganizationURLs"`
}

// Validate validates this organization
func (m *Organization) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOrganizationDisplayNames(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizationNames(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizationURLs(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Organization) validateOrganizationDisplayNames(formats strfmt.Registry) error {
	if swag.IsZero(m.OrganizationDisplayNames) { // not required
		return nil
	}

	for i := 0; i < len(m.OrganizationDisplayNames); i++ {
		if swag.IsZero(m.OrganizationDisplayNames[i]) { // not required
			continue
		}

		if m.OrganizationDisplayNames[i] != nil {
			if err := m.OrganizationDisplayNames[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationDisplayNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationDisplayNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) validateOrganizationNames(formats strfmt.Registry) error {
	if swag.IsZero(m.OrganizationNames) { // not required
		return nil
	}

	for i := 0; i < len(m.OrganizationNames); i++ {
		if swag.IsZero(m.OrganizationNames[i]) { // not required
			continue
		}

		if m.OrganizationNames[i] != nil {
			if err := m.OrganizationNames[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) validateOrganizationURLs(formats strfmt.Registry) error {
	if swag.IsZero(m.OrganizationURLs) { // not required
		return nil
	}

	for i := 0; i < len(m.OrganizationURLs); i++ {
		if swag.IsZero(m.OrganizationURLs[i]) { // not required
			continue
		}

		if m.OrganizationURLs[i] != nil {
			if err := m.OrganizationURLs[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationURLs" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationURLs" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this organization based on the context it is used
func (m *Organization) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateOrganizationDisplayNames(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganizationNames(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOrganizationURLs(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Organization) contextValidateOrganizationDisplayNames(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OrganizationDisplayNames); i++ {

		if m.OrganizationDisplayNames[i] != nil {

			if swag.IsZero(m.OrganizationDisplayNames[i]) { // not required
				return nil
			}

			if err := m.OrganizationDisplayNames[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationDisplayNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationDisplayNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) contextValidateOrganizationNames(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OrganizationNames); i++ {

		if m.OrganizationNames[i] != nil {

			if swag.IsZero(m.OrganizationNames[i]) { // not required
				return nil
			}

			if err := m.OrganizationNames[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationNames" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationNames" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *Organization) contextValidateOrganizationURLs(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OrganizationURLs); i++ {

		if m.OrganizationURLs[i] != nil {

			if swag.IsZero(m.OrganizationURLs[i]) { // not required
				return nil
			}

			if err := m.OrganizationURLs[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("OrganizationURLs" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("OrganizationURLs" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *Organization) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Organization) UnmarshalBinary(b []byte) error {
	var res Organization
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}