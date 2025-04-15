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

// UpdateUser update user
//
// swagger:model UpdateUser
type UpdateUser struct {

	// business metadata
	BusinessMetadata map[string]interface{} `json:"business_metadata,omitempty" yaml:"business_metadata,omitempty"`

	// business metadata schema id
	BusinessMetadataSchemaID string `json:"business_metadata_schema_id,omitempty" yaml:"business_metadata_schema_id,omitempty"`

	// metadata
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// metadata schema id
	MetadataSchemaID string `json:"metadata_schema_id,omitempty" yaml:"metadata_schema_id,omitempty"`

	// payload
	Payload map[string]interface{} `json:"payload,omitempty" yaml:"payload,omitempty"`

	// payload schema id
	PayloadSchemaID string `json:"payload_schema_id,omitempty" yaml:"payload_schema_id,omitempty"`

	// status
	// Enum: ["active","inactive","deleted","new"]
	Status string `json:"status,omitempty" yaml:"status,omitempty"`
}

// Validate validates this update user
func (m *UpdateUser) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateStatus(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var updateUserTypeStatusPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["active","inactive","deleted","new"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateUserTypeStatusPropEnum = append(updateUserTypeStatusPropEnum, v)
	}
}

const (

	// UpdateUserStatusActive captures enum value "active"
	UpdateUserStatusActive string = "active"

	// UpdateUserStatusInactive captures enum value "inactive"
	UpdateUserStatusInactive string = "inactive"

	// UpdateUserStatusDeleted captures enum value "deleted"
	UpdateUserStatusDeleted string = "deleted"

	// UpdateUserStatusNew captures enum value "new"
	UpdateUserStatusNew string = "new"
)

// prop value enum
func (m *UpdateUser) validateStatusEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, updateUserTypeStatusPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *UpdateUser) validateStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.Status) { // not required
		return nil
	}

	// value enum
	if err := m.validateStatusEnum("status", "body", m.Status); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update user based on context it is used
func (m *UpdateUser) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateUser) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateUser) UnmarshalBinary(b []byte) error {
	var res UpdateUser
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
