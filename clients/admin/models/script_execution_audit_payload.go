// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ScriptExecutionAuditPayload script execution audit payload
//
// swagger:model ScriptExecutionAuditPayload
type ScriptExecutionAuditPayload struct {

	// caught err
	CaughtErr string `json:"caught_err,omitempty" yaml:"caught_err,omitempty"`

	// duration
	// Format: duration
	Duration strfmt.Duration `json:"duration,omitempty" yaml:"duration,omitempty"`

	// error
	Error string `json:"error,omitempty" yaml:"error,omitempty"`

	// executed at
	// Format: date-time
	ExecutedAt strfmt.DateTime `json:"executed_at,omitempty" yaml:"executed_at,omitempty"`

	// execution point
	// Enum: ["post_authn_ctx","allowed_idp_ids","token_minting","client_token_minting"]
	ExecutionPoint string `json:"execution_point,omitempty" yaml:"execution_point,omitempty"`

	// input
	Input map[string]interface{} `json:"input,omitempty" yaml:"input,omitempty"`

	// log level
	LogLevel string `json:"log_level,omitempty" yaml:"log_level,omitempty"`

	// output
	Output map[string]interface{} `json:"output,omitempty" yaml:"output,omitempty"`

	// script id
	ScriptID string `json:"script_id,omitempty" yaml:"script_id,omitempty"`

	// script name
	ScriptName string `json:"script_name,omitempty" yaml:"script_name,omitempty"`

	// stderr
	Stderr string `json:"stderr,omitempty" yaml:"stderr,omitempty"`

	// stdout
	Stdout string `json:"stdout,omitempty" yaml:"stdout,omitempty"`
}

// Validate validates this script execution audit payload
func (m *ScriptExecutionAuditPayload) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDuration(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExecutedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExecutionPoint(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ScriptExecutionAuditPayload) validateDuration(formats strfmt.Registry) error {
	if swag.IsZero(m.Duration) { // not required
		return nil
	}

	if err := validate.FormatOf("duration", "body", "duration", m.Duration.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ScriptExecutionAuditPayload) validateExecutedAt(formats strfmt.Registry) error {
	if swag.IsZero(m.ExecutedAt) { // not required
		return nil
	}

	if err := validate.FormatOf("executed_at", "body", "date-time", m.ExecutedAt.String(), formats); err != nil {
		return err
	}

	return nil
}

var scriptExecutionAuditPayloadTypeExecutionPointPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["post_authn_ctx","allowed_idp_ids","token_minting","client_token_minting"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		scriptExecutionAuditPayloadTypeExecutionPointPropEnum = append(scriptExecutionAuditPayloadTypeExecutionPointPropEnum, v)
	}
}

const (

	// ScriptExecutionAuditPayloadExecutionPointPostAuthnCtx captures enum value "post_authn_ctx"
	ScriptExecutionAuditPayloadExecutionPointPostAuthnCtx string = "post_authn_ctx"

	// ScriptExecutionAuditPayloadExecutionPointAllowedIdpIds captures enum value "allowed_idp_ids"
	ScriptExecutionAuditPayloadExecutionPointAllowedIdpIds string = "allowed_idp_ids"

	// ScriptExecutionAuditPayloadExecutionPointTokenMinting captures enum value "token_minting"
	ScriptExecutionAuditPayloadExecutionPointTokenMinting string = "token_minting"

	// ScriptExecutionAuditPayloadExecutionPointClientTokenMinting captures enum value "client_token_minting"
	ScriptExecutionAuditPayloadExecutionPointClientTokenMinting string = "client_token_minting"
)

// prop value enum
func (m *ScriptExecutionAuditPayload) validateExecutionPointEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, scriptExecutionAuditPayloadTypeExecutionPointPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ScriptExecutionAuditPayload) validateExecutionPoint(formats strfmt.Registry) error {
	if swag.IsZero(m.ExecutionPoint) { // not required
		return nil
	}

	// value enum
	if err := m.validateExecutionPointEnum("execution_point", "body", m.ExecutionPoint); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this script execution audit payload based on context it is used
func (m *ScriptExecutionAuditPayload) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ScriptExecutionAuditPayload) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ScriptExecutionAuditPayload) UnmarshalBinary(b []byte) error {
	var res ScriptExecutionAuditPayload
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
