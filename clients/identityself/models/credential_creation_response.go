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

// CredentialCreationResponse credential creation response
//
// swagger:model CredentialCreationResponse
type CredentialCreationResponse struct {

	// authenticator attachment
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty" yaml:"authenticatorAttachment,omitempty"`

	// client extension results
	ClientExtensionResults AuthenticationExtensionsClientOutputs `json:"clientExtensionResults,omitempty" yaml:"clientExtensionResults,omitempty"`

	// ID is The credential’s identifier. The requirements for the
	// identifier are distinct for each type of credential. It might
	// represent a username for username/password tuples, for example.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`

	// raw Id
	RawID URLEncodedBase64 `json:"rawId,omitempty" yaml:"rawId,omitempty"`

	// response
	Response *AuthenticatorAttestationResponse `json:"response,omitempty" yaml:"response,omitempty"`

	// Type is the value of the object’s interface object's [[type]] slot,
	// which specifies the credential type represented by this object.
	// This should be type "public-key" for Webauthn credentials.
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
}

// Validate validates this credential creation response
func (m *CredentialCreationResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClientExtensionResults(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRawID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResponse(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CredentialCreationResponse) validateClientExtensionResults(formats strfmt.Registry) error {
	if swag.IsZero(m.ClientExtensionResults) { // not required
		return nil
	}

	if m.ClientExtensionResults != nil {
		if err := m.ClientExtensionResults.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("clientExtensionResults")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("clientExtensionResults")
			}
			return err
		}
	}

	return nil
}

func (m *CredentialCreationResponse) validateRawID(formats strfmt.Registry) error {
	if swag.IsZero(m.RawID) { // not required
		return nil
	}

	if err := m.RawID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("rawId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("rawId")
		}
		return err
	}

	return nil
}

func (m *CredentialCreationResponse) validateResponse(formats strfmt.Registry) error {
	if swag.IsZero(m.Response) { // not required
		return nil
	}

	if m.Response != nil {
		if err := m.Response.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("response")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("response")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this credential creation response based on the context it is used
func (m *CredentialCreationResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClientExtensionResults(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRawID(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateResponse(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CredentialCreationResponse) contextValidateClientExtensionResults(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.ClientExtensionResults) { // not required
		return nil
	}

	if err := m.ClientExtensionResults.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("clientExtensionResults")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("clientExtensionResults")
		}
		return err
	}

	return nil
}

func (m *CredentialCreationResponse) contextValidateRawID(ctx context.Context, formats strfmt.Registry) error {

	if err := m.RawID.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("rawId")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("rawId")
		}
		return err
	}

	return nil
}

func (m *CredentialCreationResponse) contextValidateResponse(ctx context.Context, formats strfmt.Registry) error {

	if m.Response != nil {

		if swag.IsZero(m.Response) { // not required
			return nil
		}

		if err := m.Response.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("response")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("response")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CredentialCreationResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CredentialCreationResponse) UnmarshalBinary(b []byte) error {
	var res CredentialCreationResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
