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

// GetOBBRCustomerPaymentConsentResponseV3 get o b b r customer payment consent response v3
//
// swagger:model GetOBBRCustomerPaymentConsentResponseV3
type GetOBBRCustomerPaymentConsentResponseV3 struct {

	// List of account identifiers
	AccountIds []string `json:"account_ids" yaml:"account_ids"`

	// authentication context
	AuthenticationContext AuthenticationContext `json:"authentication_context,omitempty" yaml:"authentication_context,omitempty"`

	// Client application identifier.
	// Example: \"cauqo9c9vpbs0aj2b2v0\
	ClientID string `json:"client_id,omitempty" yaml:"client_id,omitempty"`

	// client info
	ClientInfo *ClientInfo `json:"client_info,omitempty" yaml:"client_info,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty" yaml:"consent_id,omitempty"`

	// Consent creation time
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty" yaml:"created_at,omitempty"`

	// customer payment consent v3
	CustomerPaymentConsentV3 *BrazilCustomerPaymentConsentV3 `json:"customer_payment_consent_v3,omitempty" yaml:"customer_payment_consent_v3,omitempty"`

	// List of requested scopes
	RequestedScopes []*RequestedScope `json:"requested_scopes" yaml:"requested_scopes"`

	// Server / Workspace identifier.
	// Example: \"server\
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// Consent status
	Status string `json:"status,omitempty" yaml:"status,omitempty"`

	// Subject
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`

	// Tenant identifier.
	// Example: \"tenant\
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this get o b b r customer payment consent response v3
func (m *GetOBBRCustomerPaymentConsentResponseV3) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAuthenticationContext(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClientInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCustomerPaymentConsentV3(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRequestedScopes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateAuthenticationContext(formats strfmt.Registry) error {
	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if m.AuthenticationContext != nil {
		if err := m.AuthenticationContext.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("authentication_context")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("authentication_context")
			}
			return err
		}
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateClientInfo(formats strfmt.Registry) error {
	if swag.IsZero(m.ClientInfo) { // not required
		return nil
	}

	if m.ClientInfo != nil {
		if err := m.ClientInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateCustomerPaymentConsentV3(formats strfmt.Registry) error {
	if swag.IsZero(m.CustomerPaymentConsentV3) { // not required
		return nil
	}

	if m.CustomerPaymentConsentV3 != nil {
		if err := m.CustomerPaymentConsentV3.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v3")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v3")
			}
			return err
		}
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateRequestedScopes(formats strfmt.Registry) error {
	if swag.IsZero(m.RequestedScopes) { // not required
		return nil
	}

	for i := 0; i < len(m.RequestedScopes); i++ {
		if swag.IsZero(m.RequestedScopes[i]) { // not required
			continue
		}

		if m.RequestedScopes[i] != nil {
			if err := m.RequestedScopes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("type")
		}
		return err
	}

	return nil
}

// ContextValidate validate this get o b b r customer payment consent response v3 based on the context it is used
func (m *GetOBBRCustomerPaymentConsentResponseV3) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClientInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCustomerPaymentConsentV3(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRequestedScopes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) contextValidateAuthenticationContext(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.AuthenticationContext) { // not required
		return nil
	}

	if err := m.AuthenticationContext.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("authentication_context")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("authentication_context")
		}
		return err
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) contextValidateClientInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.ClientInfo != nil {

		if swag.IsZero(m.ClientInfo) { // not required
			return nil
		}

		if err := m.ClientInfo.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("client_info")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("client_info")
			}
			return err
		}
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) contextValidateCustomerPaymentConsentV3(ctx context.Context, formats strfmt.Registry) error {

	if m.CustomerPaymentConsentV3 != nil {

		if swag.IsZero(m.CustomerPaymentConsentV3) { // not required
			return nil
		}

		if err := m.CustomerPaymentConsentV3.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("customer_payment_consent_v3")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("customer_payment_consent_v3")
			}
			return err
		}
	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) contextValidateRequestedScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RequestedScopes); i++ {

		if m.RequestedScopes[i] != nil {

			if swag.IsZero(m.RequestedScopes[i]) { // not required
				return nil
			}

			if err := m.RequestedScopes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("requested_scopes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GetOBBRCustomerPaymentConsentResponseV3) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.Type) { // not required
		return nil
	}

	if err := m.Type.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("type")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("type")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GetOBBRCustomerPaymentConsentResponseV3) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetOBBRCustomerPaymentConsentResponseV3) UnmarshalBinary(b []byte) error {
	var res GetOBBRCustomerPaymentConsentResponseV3
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
