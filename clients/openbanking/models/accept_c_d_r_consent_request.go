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

// AcceptCDRConsentRequest accept c d r consent request
//
// swagger:model AcceptCDRConsentRequest
type AcceptCDRConsentRequest struct {

	// List of accounts that user agreed to share on the consent page.
	// Account identifiers should be passed to Cloudentity in encrypted form.
	AccountIds []string `json:"account_ids"`

	// User's customer identifier.
	// CustomerID can be provided by the login page and optionally overridden by the consent page.
	//
	// exampe: customer1
	CustomerID string `json:"customer_id,omitempty"`

	// granted scopes
	GrantedScopes GrantedScopes `json:"granted_scopes,omitempty"`

	// Random string generated by Cloudentity used to mitigate Cross-site request forgery (CSRF) attacks.
	// Cloudentity sends state as `login_state` query param when redirecting to the consent page.
	// Example: cauq8fonbud6q8806bf0
	LoginState string `json:"login_state,omitempty"`
}

// Validate validates this accept c d r consent request
func (m *AcceptCDRConsentRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGrantedScopes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptCDRConsentRequest) validateGrantedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.GrantedScopes) { // not required
		return nil
	}

	if err := m.GrantedScopes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_scopes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_scopes")
		}
		return err
	}

	return nil
}

// ContextValidate validate this accept c d r consent request based on the context it is used
func (m *AcceptCDRConsentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGrantedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptCDRConsentRequest) contextValidateGrantedScopes(ctx context.Context, formats strfmt.Registry) error {

	if err := m.GrantedScopes.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("granted_scopes")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("granted_scopes")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AcceptCDRConsentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AcceptCDRConsentRequest) UnmarshalBinary(b []byte) error {
	var res AcceptCDRConsentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
