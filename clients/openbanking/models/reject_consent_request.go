// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RejectConsentRequest reject consent request
//
// swagger:model RejectConsentRequest
type RejectConsentRequest struct {

	// Rejection error
	// Example: rejected
	Error string `json:"error,omitempty"`

	// Rejection cause
	ErrorCause string `json:"error_cause,omitempty"`

	// Rejection error description
	ErrorDescription string `json:"error_description,omitempty"`

	// login identifier
	ID string `json:"id,omitempty"`

	// Random string generated by Cloudentity used to mitigate Cross-site request forgery (CSRF) attacks.
	// Cloudentity sends state as `login_state` query parameter when redirecting to the consent page.
	// Example: cauq8fonbud6q8806bf0
	LoginState string `json:"login_state,omitempty"`

	// Rejection http status code
	// Example: 403
	StatusCode int64 `json:"status_code,omitempty"`
}

// Validate validates this reject consent request
func (m *RejectConsentRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this reject consent request based on context it is used
func (m *RejectConsentRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RejectConsentRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RejectConsentRequest) UnmarshalBinary(b []byte) error {
	var res RejectConsentRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
