// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TestPolicyInputRequest test policy input request
//
// swagger:model TestPolicyInputRequest
type TestPolicyInputRequest struct {

	// Headers that are used in your request that you use to test your policy
	Headers map[string][]string `json:"headers,omitempty"`

	// Method that is used in your request that you use to test your policy
	Method string `json:"method,omitempty"`

	// Path that is used in your request that you use to test your policy
	Path string `json:"path,omitempty"`

	// Path parameters that are used in your request that you use to test your policy
	PathParams map[string]string `json:"path_params,omitempty"`

	// Query parameters that are used in your request that you use to test your policy
	QueryParams map[string][]string `json:"query_params,omitempty"`
}

// Validate validates this test policy input request
func (m *TestPolicyInputRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this test policy input request based on context it is used
func (m *TestPolicyInputRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TestPolicyInputRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TestPolicyInputRequest) UnmarshalBinary(b []byte) error {
	var res TestPolicyInputRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
