// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
)

// GrantedScopes granted scopes
//
// swagger:model GrantedScopes
type GrantedScopes []string

// Validate validates this granted scopes
func (m GrantedScopes) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this granted scopes based on context it is used
func (m GrantedScopes) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
