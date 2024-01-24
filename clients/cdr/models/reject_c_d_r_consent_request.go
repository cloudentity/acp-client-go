// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RejectCDRConsentRequest reject c d r consent request
//
// swagger:model RejectCDRConsentRequest
type RejectCDRConsentRequest struct {

	// Rejection error indication.
	// Example: rejected
	Error string `json:"error,omitempty" yaml:"error,omitempty"`

	// Rejection reasons.
	// Example: User personal considerations
	ErrorCause string `json:"error_cause,omitempty" yaml:"error_cause,omitempty"`

	// Rejection error description.
	// Example: No access to email
	ErrorDescription string `json:"error_description,omitempty" yaml:"error_description,omitempty"`

	// A string of characters randomly generated by Cloudentity to mitigate cross-site request forgery (CSRF) attacks.
	// Cloudentity passes this value with the `login_state` query parameter when redirecting a user to the consent page.
	// Example: cauq8fonbud6q8806bf0
	LoginState string `json:"login_state,omitempty" yaml:"login_state,omitempty"`

	// Rejection HTTP status code.
	// Example: 403
	StatusCode int64 `json:"status_code,omitempty" yaml:"status_code,omitempty"`
}

// Validate validates this reject c d r consent request
func (m *RejectCDRConsentRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this reject c d r consent request based on context it is used
func (m *RejectCDRConsentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RejectCDRConsentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RejectCDRConsentRequest) UnmarshalBinary(b []byte) error {
	var res RejectCDRConsentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
