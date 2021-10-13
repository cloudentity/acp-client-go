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

// IDPDiscoverySettings ID p discovery settings
//
// swagger:model IDPDiscoverySettings
type IDPDiscoverySettings struct {

	// An array of email domains configured for an IDP for the purposes of IDP discovery
	//
	// If a domain is connected to an IDP and this domain is used during the login process, the IDP
	// is automatically discovered and the user is either presented with a suggested IDP or is
	// instantly redirected to their IDP configured for the user's email domain.
	Domains []IDPDomain `json:"domains"`

	// If the intelligent IDP discovery is enabled and the instant redirect flag is on, the user is
	// instantly redirected to a proper Identity Provider as soon as a match is hit based on the
	// domain when a user is typing their email in the username field
	InstantRedirect bool `json:"instant_redirect,omitempty"`
}

// Validate validates this ID p discovery settings
func (m *IDPDiscoverySettings) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDomains(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IDPDiscoverySettings) validateDomains(formats strfmt.Registry) error {
	if swag.IsZero(m.Domains) { // not required
		return nil
	}

	for i := 0; i < len(m.Domains); i++ {

		if err := m.Domains[i].Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domains" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// ContextValidate validate this ID p discovery settings based on the context it is used
func (m *IDPDiscoverySettings) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDomains(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *IDPDiscoverySettings) contextValidateDomains(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Domains); i++ {

		if err := m.Domains[i].ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("domains" + "." + strconv.Itoa(i))
			}
			return err
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *IDPDiscoverySettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IDPDiscoverySettings) UnmarshalBinary(b []byte) error {
	var res IDPDiscoverySettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}