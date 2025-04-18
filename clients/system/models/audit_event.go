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

// AuditEvent audit event
//
// swagger:model AuditEvent
type AuditEvent struct {

	// Name of an action that was performed for a given event subject.
	// Example: created
	// Enum: ["authenticated","challenged","authorized","unauthorized","created","updated","deleted","generated","requested","confirmed","accepted","rejected","revoked","notified","issued","denied","granted","attempted","failed","succeeded","sent","not_sent","executed","calculated","reset_requested","reset_completed","add_requested","add_completed","added_to_group","removed_from_group"]
	Action string `json:"action,omitempty" yaml:"action,omitempty"`

	// Additional audit event context.
	Context map[string]string `json:"context,omitempty" yaml:"context,omitempty"`

	// Event ID - unique audit event identifier.
	EventID string `json:"event_id,omitempty" yaml:"event_id,omitempty"`

	// Resource or entity that is a subject of a given audit event.
	// Example: client
	// Enum: ["request","gateway_request","gateway_policy","policy","client","credential","login","risk","post_authn","recovery","consent","client_consents","customer_consents","authorization_code","access_token","saml_assertion","scopes","claims","otp","user","schema","pool","password","bruteforce","dcr","script","role","task","jit","tokens","service","server","import","organization","otp_inspect","totp","webauthn","group"]
	EventSubject string `json:"event_subject,omitempty" yaml:"event_subject,omitempty"`

	// metadata
	Metadata *AuditEventMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// payload
	Payload *AuditEventPayloads `json:"payload,omitempty" yaml:"payload,omitempty"`

	// Server ID.
	ServerID string `json:"server_id,omitempty" yaml:"server_id,omitempty"`

	// Tenant ID.
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`

	// Time when the event took place.
	// Format: date-time
	Timestamp strfmt.DateTime `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}

// Validate validates this audit event
func (m *AuditEvent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAction(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventSubject(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMetadata(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayload(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimestamp(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var auditEventTypeActionPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["authenticated","challenged","authorized","unauthorized","created","updated","deleted","generated","requested","confirmed","accepted","rejected","revoked","notified","issued","denied","granted","attempted","failed","succeeded","sent","not_sent","executed","calculated","reset_requested","reset_completed","add_requested","add_completed","added_to_group","removed_from_group"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		auditEventTypeActionPropEnum = append(auditEventTypeActionPropEnum, v)
	}
}

const (

	// AuditEventActionAuthenticated captures enum value "authenticated"
	AuditEventActionAuthenticated string = "authenticated"

	// AuditEventActionChallenged captures enum value "challenged"
	AuditEventActionChallenged string = "challenged"

	// AuditEventActionAuthorized captures enum value "authorized"
	AuditEventActionAuthorized string = "authorized"

	// AuditEventActionUnauthorized captures enum value "unauthorized"
	AuditEventActionUnauthorized string = "unauthorized"

	// AuditEventActionCreated captures enum value "created"
	AuditEventActionCreated string = "created"

	// AuditEventActionUpdated captures enum value "updated"
	AuditEventActionUpdated string = "updated"

	// AuditEventActionDeleted captures enum value "deleted"
	AuditEventActionDeleted string = "deleted"

	// AuditEventActionGenerated captures enum value "generated"
	AuditEventActionGenerated string = "generated"

	// AuditEventActionRequested captures enum value "requested"
	AuditEventActionRequested string = "requested"

	// AuditEventActionConfirmed captures enum value "confirmed"
	AuditEventActionConfirmed string = "confirmed"

	// AuditEventActionAccepted captures enum value "accepted"
	AuditEventActionAccepted string = "accepted"

	// AuditEventActionRejected captures enum value "rejected"
	AuditEventActionRejected string = "rejected"

	// AuditEventActionRevoked captures enum value "revoked"
	AuditEventActionRevoked string = "revoked"

	// AuditEventActionNotified captures enum value "notified"
	AuditEventActionNotified string = "notified"

	// AuditEventActionIssued captures enum value "issued"
	AuditEventActionIssued string = "issued"

	// AuditEventActionDenied captures enum value "denied"
	AuditEventActionDenied string = "denied"

	// AuditEventActionGranted captures enum value "granted"
	AuditEventActionGranted string = "granted"

	// AuditEventActionAttempted captures enum value "attempted"
	AuditEventActionAttempted string = "attempted"

	// AuditEventActionFailed captures enum value "failed"
	AuditEventActionFailed string = "failed"

	// AuditEventActionSucceeded captures enum value "succeeded"
	AuditEventActionSucceeded string = "succeeded"

	// AuditEventActionSent captures enum value "sent"
	AuditEventActionSent string = "sent"

	// AuditEventActionNotSent captures enum value "not_sent"
	AuditEventActionNotSent string = "not_sent"

	// AuditEventActionExecuted captures enum value "executed"
	AuditEventActionExecuted string = "executed"

	// AuditEventActionCalculated captures enum value "calculated"
	AuditEventActionCalculated string = "calculated"

	// AuditEventActionResetRequested captures enum value "reset_requested"
	AuditEventActionResetRequested string = "reset_requested"

	// AuditEventActionResetCompleted captures enum value "reset_completed"
	AuditEventActionResetCompleted string = "reset_completed"

	// AuditEventActionAddRequested captures enum value "add_requested"
	AuditEventActionAddRequested string = "add_requested"

	// AuditEventActionAddCompleted captures enum value "add_completed"
	AuditEventActionAddCompleted string = "add_completed"

	// AuditEventActionAddedToGroup captures enum value "added_to_group"
	AuditEventActionAddedToGroup string = "added_to_group"

	// AuditEventActionRemovedFromGroup captures enum value "removed_from_group"
	AuditEventActionRemovedFromGroup string = "removed_from_group"
)

// prop value enum
func (m *AuditEvent) validateActionEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, auditEventTypeActionPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AuditEvent) validateAction(formats strfmt.Registry) error {
	if swag.IsZero(m.Action) { // not required
		return nil
	}

	// value enum
	if err := m.validateActionEnum("action", "body", m.Action); err != nil {
		return err
	}

	return nil
}

var auditEventTypeEventSubjectPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["request","gateway_request","gateway_policy","policy","client","credential","login","risk","post_authn","recovery","consent","client_consents","customer_consents","authorization_code","access_token","saml_assertion","scopes","claims","otp","user","schema","pool","password","bruteforce","dcr","script","role","task","jit","tokens","service","server","import","organization","otp_inspect","totp","webauthn","group"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		auditEventTypeEventSubjectPropEnum = append(auditEventTypeEventSubjectPropEnum, v)
	}
}

const (

	// AuditEventEventSubjectRequest captures enum value "request"
	AuditEventEventSubjectRequest string = "request"

	// AuditEventEventSubjectGatewayRequest captures enum value "gateway_request"
	AuditEventEventSubjectGatewayRequest string = "gateway_request"

	// AuditEventEventSubjectGatewayPolicy captures enum value "gateway_policy"
	AuditEventEventSubjectGatewayPolicy string = "gateway_policy"

	// AuditEventEventSubjectPolicy captures enum value "policy"
	AuditEventEventSubjectPolicy string = "policy"

	// AuditEventEventSubjectClient captures enum value "client"
	AuditEventEventSubjectClient string = "client"

	// AuditEventEventSubjectCredential captures enum value "credential"
	AuditEventEventSubjectCredential string = "credential"

	// AuditEventEventSubjectLogin captures enum value "login"
	AuditEventEventSubjectLogin string = "login"

	// AuditEventEventSubjectRisk captures enum value "risk"
	AuditEventEventSubjectRisk string = "risk"

	// AuditEventEventSubjectPostAuthn captures enum value "post_authn"
	AuditEventEventSubjectPostAuthn string = "post_authn"

	// AuditEventEventSubjectRecovery captures enum value "recovery"
	AuditEventEventSubjectRecovery string = "recovery"

	// AuditEventEventSubjectConsent captures enum value "consent"
	AuditEventEventSubjectConsent string = "consent"

	// AuditEventEventSubjectClientConsents captures enum value "client_consents"
	AuditEventEventSubjectClientConsents string = "client_consents"

	// AuditEventEventSubjectCustomerConsents captures enum value "customer_consents"
	AuditEventEventSubjectCustomerConsents string = "customer_consents"

	// AuditEventEventSubjectAuthorizationCode captures enum value "authorization_code"
	AuditEventEventSubjectAuthorizationCode string = "authorization_code"

	// AuditEventEventSubjectAccessToken captures enum value "access_token"
	AuditEventEventSubjectAccessToken string = "access_token"

	// AuditEventEventSubjectSamlAssertion captures enum value "saml_assertion"
	AuditEventEventSubjectSamlAssertion string = "saml_assertion"

	// AuditEventEventSubjectScopes captures enum value "scopes"
	AuditEventEventSubjectScopes string = "scopes"

	// AuditEventEventSubjectClaims captures enum value "claims"
	AuditEventEventSubjectClaims string = "claims"

	// AuditEventEventSubjectOtp captures enum value "otp"
	AuditEventEventSubjectOtp string = "otp"

	// AuditEventEventSubjectUser captures enum value "user"
	AuditEventEventSubjectUser string = "user"

	// AuditEventEventSubjectSchema captures enum value "schema"
	AuditEventEventSubjectSchema string = "schema"

	// AuditEventEventSubjectPool captures enum value "pool"
	AuditEventEventSubjectPool string = "pool"

	// AuditEventEventSubjectPassword captures enum value "password"
	AuditEventEventSubjectPassword string = "password"

	// AuditEventEventSubjectBruteforce captures enum value "bruteforce"
	AuditEventEventSubjectBruteforce string = "bruteforce"

	// AuditEventEventSubjectDcr captures enum value "dcr"
	AuditEventEventSubjectDcr string = "dcr"

	// AuditEventEventSubjectScript captures enum value "script"
	AuditEventEventSubjectScript string = "script"

	// AuditEventEventSubjectRole captures enum value "role"
	AuditEventEventSubjectRole string = "role"

	// AuditEventEventSubjectTask captures enum value "task"
	AuditEventEventSubjectTask string = "task"

	// AuditEventEventSubjectJit captures enum value "jit"
	AuditEventEventSubjectJit string = "jit"

	// AuditEventEventSubjectTokens captures enum value "tokens"
	AuditEventEventSubjectTokens string = "tokens"

	// AuditEventEventSubjectService captures enum value "service"
	AuditEventEventSubjectService string = "service"

	// AuditEventEventSubjectServer captures enum value "server"
	AuditEventEventSubjectServer string = "server"

	// AuditEventEventSubjectImport captures enum value "import"
	AuditEventEventSubjectImport string = "import"

	// AuditEventEventSubjectOrganization captures enum value "organization"
	AuditEventEventSubjectOrganization string = "organization"

	// AuditEventEventSubjectOtpInspect captures enum value "otp_inspect"
	AuditEventEventSubjectOtpInspect string = "otp_inspect"

	// AuditEventEventSubjectTotp captures enum value "totp"
	AuditEventEventSubjectTotp string = "totp"

	// AuditEventEventSubjectWebauthn captures enum value "webauthn"
	AuditEventEventSubjectWebauthn string = "webauthn"

	// AuditEventEventSubjectGroup captures enum value "group"
	AuditEventEventSubjectGroup string = "group"
)

// prop value enum
func (m *AuditEvent) validateEventSubjectEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, auditEventTypeEventSubjectPropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *AuditEvent) validateEventSubject(formats strfmt.Registry) error {
	if swag.IsZero(m.EventSubject) { // not required
		return nil
	}

	// value enum
	if err := m.validateEventSubjectEnum("event_subject", "body", m.EventSubject); err != nil {
		return err
	}

	return nil
}

func (m *AuditEvent) validateMetadata(formats strfmt.Registry) error {
	if swag.IsZero(m.Metadata) { // not required
		return nil
	}

	if m.Metadata != nil {
		if err := m.Metadata.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

func (m *AuditEvent) validatePayload(formats strfmt.Registry) error {
	if swag.IsZero(m.Payload) { // not required
		return nil
	}

	if m.Payload != nil {
		if err := m.Payload.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payload")
			}
			return err
		}
	}

	return nil
}

func (m *AuditEvent) validateTimestamp(formats strfmt.Registry) error {
	if swag.IsZero(m.Timestamp) { // not required
		return nil
	}

	if err := validate.FormatOf("timestamp", "body", "date-time", m.Timestamp.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this audit event based on the context it is used
func (m *AuditEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateMetadata(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePayload(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuditEvent) contextValidateMetadata(ctx context.Context, formats strfmt.Registry) error {

	if m.Metadata != nil {

		if swag.IsZero(m.Metadata) { // not required
			return nil
		}

		if err := m.Metadata.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("metadata")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("metadata")
			}
			return err
		}
	}

	return nil
}

func (m *AuditEvent) contextValidatePayload(ctx context.Context, formats strfmt.Registry) error {

	if m.Payload != nil {

		if swag.IsZero(m.Payload) { // not required
			return nil
		}

		if err := m.Payload.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("payload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("payload")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuditEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuditEvent) UnmarshalBinary(b []byte) error {
	var res AuditEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
