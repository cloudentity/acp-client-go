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

// GetFDXConsentResponse get f d x consent response
//
// swagger:model GetFDXConsentResponse
type GetFDXConsentResponse struct {

	// List of account identifiers
	AccountIds []string `json:"account_ids"`

	// authentication context
	AuthenticationContext AuthenticationContext `json:"authentication_context,omitempty"`

	// Client identifier
	// Example: \"cauqo9c9vpbs0aj2b2v0\
	ClientID string `json:"client_id,omitempty"`

	// client info
	ClientInfo *ClientInfo `json:"client_info,omitempty"`

	// consent id
	ConsentID string `json:"consent_id,omitempty"`

	// Consent creation time
	// Format: date-time
	CreatedAt strfmt.DateTime `json:"created_at,omitempty"`

	// fdx consent
	FdxConsent *FDXConsent `json:"fdx_consent,omitempty"`

	// List of requested scopes
	RequestedScopes []*RequestedScope `json:"requested_scopes"`

	// Server / Workspace identifier
	// Example: \"server\
	ServerID string `json:"server_id,omitempty"`

	// Consent status
	Status string `json:"status,omitempty"`

	// Subject
	Subject string `json:"subject,omitempty"`

	// Tenant identifier
	// Example: \"tenant\
	TenantID string `json:"tenant_id,omitempty"`

	// type
	Type ConsentType `json:"type,omitempty"`
}

// Validate validates this get f d x consent response
func (m *GetFDXConsentResponse) Validate(formats strfmt.Registry) error {
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

	if err := m.validateFdxConsent(formats); err != nil {
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

func (m *GetFDXConsentResponse) validateAuthenticationContext(formats strfmt.Registry) error {
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

func (m *GetFDXConsentResponse) validateClientInfo(formats strfmt.Registry) error {
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

func (m *GetFDXConsentResponse) validateCreatedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("created_at", "body", "date-time", m.CreatedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *GetFDXConsentResponse) validateFdxConsent(formats strfmt.Registry) error {
	if swag.IsZero(m.FdxConsent) { // not required
		return nil
	}

	if m.FdxConsent != nil {
		if err := m.FdxConsent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdx_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdx_consent")
			}
			return err
		}
	}

	return nil
}

func (m *GetFDXConsentResponse) validateRequestedScopes(formats strfmt.Registry) error {
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

func (m *GetFDXConsentResponse) validateType(formats strfmt.Registry) error {
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

// ContextValidate validate this get f d x consent response based on the context it is used
func (m *GetFDXConsentResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAuthenticationContext(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateClientInfo(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFdxConsent(ctx, formats); err != nil {
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

func (m *GetFDXConsentResponse) contextValidateAuthenticationContext(ctx context.Context, formats strfmt.Registry) error {

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

func (m *GetFDXConsentResponse) contextValidateClientInfo(ctx context.Context, formats strfmt.Registry) error {

	if m.ClientInfo != nil {
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

func (m *GetFDXConsentResponse) contextValidateFdxConsent(ctx context.Context, formats strfmt.Registry) error {

	if m.FdxConsent != nil {
		if err := m.FdxConsent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("fdx_consent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("fdx_consent")
			}
			return err
		}
	}

	return nil
}

func (m *GetFDXConsentResponse) contextValidateRequestedScopes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RequestedScopes); i++ {

		if m.RequestedScopes[i] != nil {
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

func (m *GetFDXConsentResponse) contextValidateType(ctx context.Context, formats strfmt.Registry) error {

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
func (m *GetFDXConsentResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GetFDXConsentResponse) UnmarshalBinary(b []byte) error {
	var res GetFDXConsentResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}