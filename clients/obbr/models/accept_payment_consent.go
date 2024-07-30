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

// AcceptPaymentConsent accept payment consent
//
// swagger:model AcceptPaymentConsent
type AcceptPaymentConsent struct {

	// List of accounts that user agreed to share on the consent page.
	AccountIds []string `json:"account_ids" yaml:"account_ids"`

	// debtor account
	DebtorAccount *DebtorAccount `json:"debtor_account,omitempty" yaml:"debtor_account,omitempty"`

	// granted scopes
	GrantedScopes GrantedScopes `json:"granted_scopes,omitempty" yaml:"granted_scopes,omitempty"`

	// Random string generated by Cloudentity used to mitigate Cross-site request forgery (CSRF) attacks.
	// Cloudentity sends state as login_state query param when redirecting to the consent page.
	// Example: \"cauq8fonbud6q8806bf0\
	LoginState string `json:"login_state,omitempty" yaml:"login_state,omitempty"`
}

// Validate validates this accept payment consent
func (m *AcceptPaymentConsent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDebtorAccount(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGrantedScopes(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptPaymentConsent) validateDebtorAccount(formats strfmt.Registry) error {
	if swag.IsZero(m.DebtorAccount) { // not required
		return nil
	}

	if m.DebtorAccount != nil {
		if err := m.DebtorAccount.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("debtor_account")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("debtor_account")
			}
			return err
		}
	}

	return nil
}

func (m *AcceptPaymentConsent) validateGrantedScopes(formats strfmt.Registry) error {
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

// ContextValidate validate this accept payment consent based on the context it is used
func (m *AcceptPaymentConsent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDebtorAccount(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGrantedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AcceptPaymentConsent) contextValidateDebtorAccount(ctx context.Context, formats strfmt.Registry) error {

	if m.DebtorAccount != nil {

		if swag.IsZero(m.DebtorAccount) { // not required
			return nil
		}

		if err := m.DebtorAccount.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("debtor_account")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("debtor_account")
			}
			return err
		}
	}

	return nil
}

func (m *AcceptPaymentConsent) contextValidateGrantedScopes(ctx context.Context, formats strfmt.Registry) error {

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
func (m *AcceptPaymentConsent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AcceptPaymentConsent) UnmarshalBinary(b []byte) error {
	var res AcceptPaymentConsent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}