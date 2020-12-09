// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// GithubSettings github settings
//
// swagger:model GithubSettings
type GithubSettings struct {

	// OAuth client identifier
	ClientID string `json:"client_id,omitempty"`

	// flag to fetch groups
	FetchGroups bool `json:"fetch_groups,omitempty"`

	// OAuth redirect URL
	RedirectURL string `json:"redirect_url,omitempty"`

	// OAuth scopes which client will be requesting
	Scopes []string `json:"scopes"`
}

// Validate validates this github settings
func (m *GithubSettings) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GithubSettings) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GithubSettings) UnmarshalBinary(b []byte) error {
	var res GithubSettings
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
