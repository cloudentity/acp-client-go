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

// SupportedJSONSchema supported JSON schema
//
// swagger:model SupportedJSONSchema
type SupportedJSONSchema struct {

	// additional properties
	AdditionalProperties bool `json:"additionalProperties,omitempty"`

	// all of
	AllOf []*SupportedJSONSchema `json:"allOf"`

	// any of
	AnyOf []*SupportedJSONSchema `json:"anyOf"`

	// const
	Const string `json:"const,omitempty"`

	// contains
	Contains *SupportedJSONSchema `json:"contains,omitempty"`

	// dependent required
	DependentRequired map[string][]string `json:"dependentRequired,omitempty"`

	// dependent schemas
	DependentSchemas map[string]SupportedJSONSchema `json:"dependentSchemas,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// else
	Else *SupportedJSONSchema `json:"else,omitempty"`

	// enum
	Enum []string `json:"enum"`

	// exclusive maximum
	ExclusiveMaximum int64 `json:"exclusiveMaximum,omitempty"`

	// exclusive minimum
	ExclusiveMinimum int64 `json:"exclusiveMinimum,omitempty"`

	// hidden
	Hidden bool `json:"hidden,omitempty"`

	// if
	If *SupportedJSONSchema `json:"if,omitempty"`

	// items
	Items *SupportedJSONSchema `json:"items,omitempty"`

	// max contains
	MaxContains int64 `json:"maxContains,omitempty"`

	// arrays
	MaxItems int64 `json:"maxItems,omitempty"`

	// strings
	MaxLength int64 `json:"maxLength,omitempty"`

	// objects
	MaxProperties int64 `json:"maxProperties,omitempty"`

	// maximum
	Maximum int64 `json:"maximum,omitempty"`

	// min contains
	MinContains int64 `json:"minContains,omitempty"`

	// min items
	MinItems int64 `json:"minItems,omitempty"`

	// min length
	MinLength int64 `json:"minLength,omitempty"`

	// min properties
	MinProperties int64 `json:"minProperties,omitempty"`

	// minimum
	Minimum int64 `json:"minimum,omitempty"`

	// numeric
	MultipleOf int64 `json:"multipleOf,omitempty"`

	// not
	Not *SupportedJSONSchema `json:"not,omitempty"`

	// one of
	OneOf []*SupportedJSONSchema `json:"oneOf"`

	// pattern
	Pattern string `json:"pattern,omitempty"`

	// pattern properties
	PatternProperties map[string]SupportedJSONSchema `json:"patternProperties,omitempty"`

	// properties
	Properties map[string]SupportedJSONSchema `json:"properties,omitempty"`

	// property names
	PropertyNames *SupportedJSONSchema `json:"propertyNames,omitempty"`

	// required
	Required []string `json:"required"`

	// then
	Then *SupportedJSONSchema `json:"then,omitempty"`

	// any
	Type string `json:"type,omitempty"`

	// unique items
	UniqueItems bool `json:"uniqueItems,omitempty"`
}

// Validate validates this supported JSON schema
func (m *SupportedJSONSchema) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAllOf(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAnyOf(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContains(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDependentSchemas(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateElse(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIf(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNot(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOneOf(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePatternProperties(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProperties(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePropertyNames(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThen(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SupportedJSONSchema) validateAllOf(formats strfmt.Registry) error {
	if swag.IsZero(m.AllOf) { // not required
		return nil
	}

	for i := 0; i < len(m.AllOf); i++ {
		if swag.IsZero(m.AllOf[i]) { // not required
			continue
		}

		if m.AllOf[i] != nil {
			if err := m.AllOf[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("allOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("allOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validateAnyOf(formats strfmt.Registry) error {
	if swag.IsZero(m.AnyOf) { // not required
		return nil
	}

	for i := 0; i < len(m.AnyOf); i++ {
		if swag.IsZero(m.AnyOf[i]) { // not required
			continue
		}

		if m.AnyOf[i] != nil {
			if err := m.AnyOf[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("anyOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("anyOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validateContains(formats strfmt.Registry) error {
	if swag.IsZero(m.Contains) { // not required
		return nil
	}

	if m.Contains != nil {
		if err := m.Contains.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("contains")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("contains")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateDependentSchemas(formats strfmt.Registry) error {
	if swag.IsZero(m.DependentSchemas) { // not required
		return nil
	}

	for k := range m.DependentSchemas {

		if err := validate.Required("dependentSchemas"+"."+k, "body", m.DependentSchemas[k]); err != nil {
			return err
		}
		if val, ok := m.DependentSchemas[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("dependentSchemas" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("dependentSchemas" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validateElse(formats strfmt.Registry) error {
	if swag.IsZero(m.Else) { // not required
		return nil
	}

	if m.Else != nil {
		if err := m.Else.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("else")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("else")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateIf(formats strfmt.Registry) error {
	if swag.IsZero(m.If) { // not required
		return nil
	}

	if m.If != nil {
		if err := m.If.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("if")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("if")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateItems(formats strfmt.Registry) error {
	if swag.IsZero(m.Items) { // not required
		return nil
	}

	if m.Items != nil {
		if err := m.Items.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("items")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("items")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateNot(formats strfmt.Registry) error {
	if swag.IsZero(m.Not) { // not required
		return nil
	}

	if m.Not != nil {
		if err := m.Not.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("not")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("not")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateOneOf(formats strfmt.Registry) error {
	if swag.IsZero(m.OneOf) { // not required
		return nil
	}

	for i := 0; i < len(m.OneOf); i++ {
		if swag.IsZero(m.OneOf[i]) { // not required
			continue
		}

		if m.OneOf[i] != nil {
			if err := m.OneOf[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("oneOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("oneOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validatePatternProperties(formats strfmt.Registry) error {
	if swag.IsZero(m.PatternProperties) { // not required
		return nil
	}

	for k := range m.PatternProperties {

		if err := validate.Required("patternProperties"+"."+k, "body", m.PatternProperties[k]); err != nil {
			return err
		}
		if val, ok := m.PatternProperties[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("patternProperties" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("patternProperties" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validateProperties(formats strfmt.Registry) error {
	if swag.IsZero(m.Properties) { // not required
		return nil
	}

	for k := range m.Properties {

		if err := validate.Required("properties"+"."+k, "body", m.Properties[k]); err != nil {
			return err
		}
		if val, ok := m.Properties[k]; ok {
			if err := val.Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("properties" + "." + k)
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("properties" + "." + k)
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) validatePropertyNames(formats strfmt.Registry) error {
	if swag.IsZero(m.PropertyNames) { // not required
		return nil
	}

	if m.PropertyNames != nil {
		if err := m.PropertyNames.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("propertyNames")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("propertyNames")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) validateThen(formats strfmt.Registry) error {
	if swag.IsZero(m.Then) { // not required
		return nil
	}

	if m.Then != nil {
		if err := m.Then.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("then")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("then")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this supported JSON schema based on the context it is used
func (m *SupportedJSONSchema) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAllOf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAnyOf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateContains(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDependentSchemas(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateElse(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateIf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateItems(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNot(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateOneOf(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePatternProperties(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateProperties(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePropertyNames(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThen(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SupportedJSONSchema) contextValidateAllOf(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AllOf); i++ {

		if m.AllOf[i] != nil {
			if err := m.AllOf[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("allOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("allOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateAnyOf(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.AnyOf); i++ {

		if m.AnyOf[i] != nil {
			if err := m.AnyOf[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("anyOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("anyOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateContains(ctx context.Context, formats strfmt.Registry) error {

	if m.Contains != nil {
		if err := m.Contains.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("contains")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("contains")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateDependentSchemas(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.DependentSchemas {

		if val, ok := m.DependentSchemas[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateElse(ctx context.Context, formats strfmt.Registry) error {

	if m.Else != nil {
		if err := m.Else.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("else")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("else")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateIf(ctx context.Context, formats strfmt.Registry) error {

	if m.If != nil {
		if err := m.If.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("if")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("if")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateItems(ctx context.Context, formats strfmt.Registry) error {

	if m.Items != nil {
		if err := m.Items.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("items")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("items")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateNot(ctx context.Context, formats strfmt.Registry) error {

	if m.Not != nil {
		if err := m.Not.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("not")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("not")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateOneOf(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.OneOf); i++ {

		if m.OneOf[i] != nil {
			if err := m.OneOf[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("oneOf" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("oneOf" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidatePatternProperties(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.PatternProperties {

		if val, ok := m.PatternProperties[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateProperties(ctx context.Context, formats strfmt.Registry) error {

	for k := range m.Properties {

		if val, ok := m.Properties[k]; ok {
			if err := val.ContextValidate(ctx, formats); err != nil {
				return err
			}
		}

	}

	return nil
}

func (m *SupportedJSONSchema) contextValidatePropertyNames(ctx context.Context, formats strfmt.Registry) error {

	if m.PropertyNames != nil {
		if err := m.PropertyNames.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("propertyNames")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("propertyNames")
			}
			return err
		}
	}

	return nil
}

func (m *SupportedJSONSchema) contextValidateThen(ctx context.Context, formats strfmt.Registry) error {

	if m.Then != nil {
		if err := m.Then.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("then")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("then")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SupportedJSONSchema) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SupportedJSONSchema) UnmarshalBinary(b []byte) error {
	var res SupportedJSONSchema
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}