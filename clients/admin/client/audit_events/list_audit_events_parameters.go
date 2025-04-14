// Code generated by go-swagger; DO NOT EDIT.

package audit_events

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewListAuditEventsParams creates a new ListAuditEventsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListAuditEventsParams() *ListAuditEventsParams {
	return &ListAuditEventsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListAuditEventsParamsWithTimeout creates a new ListAuditEventsParams object
// with the ability to set a timeout on a request.
func NewListAuditEventsParamsWithTimeout(timeout time.Duration) *ListAuditEventsParams {
	return &ListAuditEventsParams{
		timeout: timeout,
	}
}

// NewListAuditEventsParamsWithContext creates a new ListAuditEventsParams object
// with the ability to set a context for a request.
func NewListAuditEventsParamsWithContext(ctx context.Context) *ListAuditEventsParams {
	return &ListAuditEventsParams{
		Context: ctx,
	}
}

// NewListAuditEventsParamsWithHTTPClient creates a new ListAuditEventsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListAuditEventsParamsWithHTTPClient(client *http.Client) *ListAuditEventsParams {
	return &ListAuditEventsParams{
		HTTPClient: client,
	}
}

/*
ListAuditEventsParams contains all the parameters to send to the API endpoint

	for the list audit events operation.

	Typically these are written to a http.Request.
*/
type ListAuditEventsParams struct {

	/* AffectedUserID.

	     optional list audit events with a given affected user id
	AffectedUserID
	*/
	AffectedUserID *string

	/* AffectedUserPoolID.

	     optional list audit events with a given affected user identity pool id
	AffectedUserPoolID
	*/
	AffectedUserPoolID *string

	/* AfterEventID.

	     optional list audit events after a given event id
	AfterEventID
	*/
	AfterEventID *string

	/* AuthorizationCorrelationID.

	   optional list audit events with a given authorization correlation id
	*/
	AuthorizationCorrelationID *string

	/* BeforeEventID.

	     optional list events before a given event id
	BeforeEventID
	*/
	BeforeEventID *string

	/* ClientID.

	     optional list audit events with a given client id
	ClientID
	*/
	ClientID *string

	/* EventAction.

	     Optional list of event types, one of: authorized unauthorized created updated deleted requested accepted rejected issued denied granted attempted failed sent not_sent revoked generated reset_requested reset_completed add_requested add_completed
	EventType
	*/
	EventAction []string

	/* EventSubject.

	     Optional list of event subjects, one of: request client gateway_request policy consent authorization_code recovery login access_token scopes otp gateway_policy user credential dcr role jit tokens service server
	EventSubject
	*/
	EventSubject []string

	/* GroupID.

	     optional list audit events with a given group id
	GroupID
	*/
	GroupID *string

	/* IdpID.

	     optional list audit events with a given IDP id
	IDPID
	*/
	IdpID *string

	/* IdpMethod.

	     optional list audit events with a given IDP method
	IDPMethod
	*/
	IdpMethod *string

	/* IdpSubject.

	     optional list audit events with a given IDP subject
	IDPSubject
	*/
	IdpSubject *string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* IP.

	     optional list audit events with a given ip address
	IP
	*/
	IP *string

	/* Limit.

	     optional limit results, min 1, max 100
	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     optional order audit events by given direction
	Order
	*/
	Order *string

	/* OrganizationID.

	   optional organization id
	*/
	OrganizationID *string

	/* SessionID.

	     optional list audit events with a given session id

	it can be used as a correlation id for listing all login related audit events
	SessionID
	*/
	SessionID *string

	/* Sort.

	     optional sort audit events by a given field
	Sort
	*/
	Sort *string

	/* Subject.

	     optional list audit events with a given subject
	Subject
	*/
	Subject *string

	/* TimestampFrom.

	     list all events after a given time
	TimestampFrom

	     Format: date-time
	*/
	TimestampFrom *strfmt.DateTime

	/* TimestampTo.

	     list all events before a given time
	TimestampTo

	     Format: date-time
	*/
	TimestampTo *strfmt.DateTime

	/* UserID.

	     optional list audit events with a given user id
	UserID
	*/
	UserID *string

	/* UserPoolID.

	     optional list audit events with a given user identity pool id
	UserPoolID
	*/
	UserPoolID *string

	/* Wid.

	   Authorization server id

	   Default: "admin"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list audit events params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuditEventsParams) WithDefaults() *ListAuditEventsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list audit events params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuditEventsParams) SetDefaults() {
	var (
		limitDefault = int64(20)

		widDefault = string("admin")
	)

	val := ListAuditEventsParams{
		Limit: &limitDefault,
		Wid:   widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list audit events params
func (o *ListAuditEventsParams) WithTimeout(timeout time.Duration) *ListAuditEventsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list audit events params
func (o *ListAuditEventsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list audit events params
func (o *ListAuditEventsParams) WithContext(ctx context.Context) *ListAuditEventsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list audit events params
func (o *ListAuditEventsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list audit events params
func (o *ListAuditEventsParams) WithHTTPClient(client *http.Client) *ListAuditEventsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list audit events params
func (o *ListAuditEventsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAffectedUserID adds the affectedUserID to the list audit events params
func (o *ListAuditEventsParams) WithAffectedUserID(affectedUserID *string) *ListAuditEventsParams {
	o.SetAffectedUserID(affectedUserID)
	return o
}

// SetAffectedUserID adds the affectedUserId to the list audit events params
func (o *ListAuditEventsParams) SetAffectedUserID(affectedUserID *string) {
	o.AffectedUserID = affectedUserID
}

// WithAffectedUserPoolID adds the affectedUserPoolID to the list audit events params
func (o *ListAuditEventsParams) WithAffectedUserPoolID(affectedUserPoolID *string) *ListAuditEventsParams {
	o.SetAffectedUserPoolID(affectedUserPoolID)
	return o
}

// SetAffectedUserPoolID adds the affectedUserPoolId to the list audit events params
func (o *ListAuditEventsParams) SetAffectedUserPoolID(affectedUserPoolID *string) {
	o.AffectedUserPoolID = affectedUserPoolID
}

// WithAfterEventID adds the afterEventID to the list audit events params
func (o *ListAuditEventsParams) WithAfterEventID(afterEventID *string) *ListAuditEventsParams {
	o.SetAfterEventID(afterEventID)
	return o
}

// SetAfterEventID adds the afterEventId to the list audit events params
func (o *ListAuditEventsParams) SetAfterEventID(afterEventID *string) {
	o.AfterEventID = afterEventID
}

// WithAuthorizationCorrelationID adds the authorizationCorrelationID to the list audit events params
func (o *ListAuditEventsParams) WithAuthorizationCorrelationID(authorizationCorrelationID *string) *ListAuditEventsParams {
	o.SetAuthorizationCorrelationID(authorizationCorrelationID)
	return o
}

// SetAuthorizationCorrelationID adds the authorizationCorrelationId to the list audit events params
func (o *ListAuditEventsParams) SetAuthorizationCorrelationID(authorizationCorrelationID *string) {
	o.AuthorizationCorrelationID = authorizationCorrelationID
}

// WithBeforeEventID adds the beforeEventID to the list audit events params
func (o *ListAuditEventsParams) WithBeforeEventID(beforeEventID *string) *ListAuditEventsParams {
	o.SetBeforeEventID(beforeEventID)
	return o
}

// SetBeforeEventID adds the beforeEventId to the list audit events params
func (o *ListAuditEventsParams) SetBeforeEventID(beforeEventID *string) {
	o.BeforeEventID = beforeEventID
}

// WithClientID adds the clientID to the list audit events params
func (o *ListAuditEventsParams) WithClientID(clientID *string) *ListAuditEventsParams {
	o.SetClientID(clientID)
	return o
}

// SetClientID adds the clientId to the list audit events params
func (o *ListAuditEventsParams) SetClientID(clientID *string) {
	o.ClientID = clientID
}

// WithEventAction adds the eventAction to the list audit events params
func (o *ListAuditEventsParams) WithEventAction(eventAction []string) *ListAuditEventsParams {
	o.SetEventAction(eventAction)
	return o
}

// SetEventAction adds the eventAction to the list audit events params
func (o *ListAuditEventsParams) SetEventAction(eventAction []string) {
	o.EventAction = eventAction
}

// WithEventSubject adds the eventSubject to the list audit events params
func (o *ListAuditEventsParams) WithEventSubject(eventSubject []string) *ListAuditEventsParams {
	o.SetEventSubject(eventSubject)
	return o
}

// SetEventSubject adds the eventSubject to the list audit events params
func (o *ListAuditEventsParams) SetEventSubject(eventSubject []string) {
	o.EventSubject = eventSubject
}

// WithGroupID adds the groupID to the list audit events params
func (o *ListAuditEventsParams) WithGroupID(groupID *string) *ListAuditEventsParams {
	o.SetGroupID(groupID)
	return o
}

// SetGroupID adds the groupId to the list audit events params
func (o *ListAuditEventsParams) SetGroupID(groupID *string) {
	o.GroupID = groupID
}

// WithIdpID adds the idpID to the list audit events params
func (o *ListAuditEventsParams) WithIdpID(idpID *string) *ListAuditEventsParams {
	o.SetIdpID(idpID)
	return o
}

// SetIdpID adds the idpId to the list audit events params
func (o *ListAuditEventsParams) SetIdpID(idpID *string) {
	o.IdpID = idpID
}

// WithIdpMethod adds the idpMethod to the list audit events params
func (o *ListAuditEventsParams) WithIdpMethod(idpMethod *string) *ListAuditEventsParams {
	o.SetIdpMethod(idpMethod)
	return o
}

// SetIdpMethod adds the idpMethod to the list audit events params
func (o *ListAuditEventsParams) SetIdpMethod(idpMethod *string) {
	o.IdpMethod = idpMethod
}

// WithIdpSubject adds the idpSubject to the list audit events params
func (o *ListAuditEventsParams) WithIdpSubject(idpSubject *string) *ListAuditEventsParams {
	o.SetIdpSubject(idpSubject)
	return o
}

// SetIdpSubject adds the idpSubject to the list audit events params
func (o *ListAuditEventsParams) SetIdpSubject(idpSubject *string) {
	o.IdpSubject = idpSubject
}

// WithIfMatch adds the ifMatch to the list audit events params
func (o *ListAuditEventsParams) WithIfMatch(ifMatch *string) *ListAuditEventsParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list audit events params
func (o *ListAuditEventsParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIP adds the ip to the list audit events params
func (o *ListAuditEventsParams) WithIP(ip *string) *ListAuditEventsParams {
	o.SetIP(ip)
	return o
}

// SetIP adds the ip to the list audit events params
func (o *ListAuditEventsParams) SetIP(ip *string) {
	o.IP = ip
}

// WithLimit adds the limit to the list audit events params
func (o *ListAuditEventsParams) WithLimit(limit *int64) *ListAuditEventsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list audit events params
func (o *ListAuditEventsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list audit events params
func (o *ListAuditEventsParams) WithOrder(order *string) *ListAuditEventsParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list audit events params
func (o *ListAuditEventsParams) SetOrder(order *string) {
	o.Order = order
}

// WithOrganizationID adds the organizationID to the list audit events params
func (o *ListAuditEventsParams) WithOrganizationID(organizationID *string) *ListAuditEventsParams {
	o.SetOrganizationID(organizationID)
	return o
}

// SetOrganizationID adds the organizationId to the list audit events params
func (o *ListAuditEventsParams) SetOrganizationID(organizationID *string) {
	o.OrganizationID = organizationID
}

// WithSessionID adds the sessionID to the list audit events params
func (o *ListAuditEventsParams) WithSessionID(sessionID *string) *ListAuditEventsParams {
	o.SetSessionID(sessionID)
	return o
}

// SetSessionID adds the sessionId to the list audit events params
func (o *ListAuditEventsParams) SetSessionID(sessionID *string) {
	o.SessionID = sessionID
}

// WithSort adds the sort to the list audit events params
func (o *ListAuditEventsParams) WithSort(sort *string) *ListAuditEventsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list audit events params
func (o *ListAuditEventsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithSubject adds the subject to the list audit events params
func (o *ListAuditEventsParams) WithSubject(subject *string) *ListAuditEventsParams {
	o.SetSubject(subject)
	return o
}

// SetSubject adds the subject to the list audit events params
func (o *ListAuditEventsParams) SetSubject(subject *string) {
	o.Subject = subject
}

// WithTimestampFrom adds the timestampFrom to the list audit events params
func (o *ListAuditEventsParams) WithTimestampFrom(timestampFrom *strfmt.DateTime) *ListAuditEventsParams {
	o.SetTimestampFrom(timestampFrom)
	return o
}

// SetTimestampFrom adds the timestampFrom to the list audit events params
func (o *ListAuditEventsParams) SetTimestampFrom(timestampFrom *strfmt.DateTime) {
	o.TimestampFrom = timestampFrom
}

// WithTimestampTo adds the timestampTo to the list audit events params
func (o *ListAuditEventsParams) WithTimestampTo(timestampTo *strfmt.DateTime) *ListAuditEventsParams {
	o.SetTimestampTo(timestampTo)
	return o
}

// SetTimestampTo adds the timestampTo to the list audit events params
func (o *ListAuditEventsParams) SetTimestampTo(timestampTo *strfmt.DateTime) {
	o.TimestampTo = timestampTo
}

// WithUserID adds the userID to the list audit events params
func (o *ListAuditEventsParams) WithUserID(userID *string) *ListAuditEventsParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the list audit events params
func (o *ListAuditEventsParams) SetUserID(userID *string) {
	o.UserID = userID
}

// WithUserPoolID adds the userPoolID to the list audit events params
func (o *ListAuditEventsParams) WithUserPoolID(userPoolID *string) *ListAuditEventsParams {
	o.SetUserPoolID(userPoolID)
	return o
}

// SetUserPoolID adds the userPoolId to the list audit events params
func (o *ListAuditEventsParams) SetUserPoolID(userPoolID *string) {
	o.UserPoolID = userPoolID
}

// WithWid adds the wid to the list audit events params
func (o *ListAuditEventsParams) WithWid(wid string) *ListAuditEventsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list audit events params
func (o *ListAuditEventsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListAuditEventsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AffectedUserID != nil {

		// query param affected_user_id
		var qrAffectedUserID string

		if o.AffectedUserID != nil {
			qrAffectedUserID = *o.AffectedUserID
		}
		qAffectedUserID := qrAffectedUserID
		if qAffectedUserID != "" {

			if err := r.SetQueryParam("affected_user_id", qAffectedUserID); err != nil {
				return err
			}
		}
	}

	if o.AffectedUserPoolID != nil {

		// query param affected_user_pool_id
		var qrAffectedUserPoolID string

		if o.AffectedUserPoolID != nil {
			qrAffectedUserPoolID = *o.AffectedUserPoolID
		}
		qAffectedUserPoolID := qrAffectedUserPoolID
		if qAffectedUserPoolID != "" {

			if err := r.SetQueryParam("affected_user_pool_id", qAffectedUserPoolID); err != nil {
				return err
			}
		}
	}

	if o.AfterEventID != nil {

		// query param after_event_id
		var qrAfterEventID string

		if o.AfterEventID != nil {
			qrAfterEventID = *o.AfterEventID
		}
		qAfterEventID := qrAfterEventID
		if qAfterEventID != "" {

			if err := r.SetQueryParam("after_event_id", qAfterEventID); err != nil {
				return err
			}
		}
	}

	if o.AuthorizationCorrelationID != nil {

		// query param authorization_correlation_id
		var qrAuthorizationCorrelationID string

		if o.AuthorizationCorrelationID != nil {
			qrAuthorizationCorrelationID = *o.AuthorizationCorrelationID
		}
		qAuthorizationCorrelationID := qrAuthorizationCorrelationID
		if qAuthorizationCorrelationID != "" {

			if err := r.SetQueryParam("authorization_correlation_id", qAuthorizationCorrelationID); err != nil {
				return err
			}
		}
	}

	if o.BeforeEventID != nil {

		// query param before_event_id
		var qrBeforeEventID string

		if o.BeforeEventID != nil {
			qrBeforeEventID = *o.BeforeEventID
		}
		qBeforeEventID := qrBeforeEventID
		if qBeforeEventID != "" {

			if err := r.SetQueryParam("before_event_id", qBeforeEventID); err != nil {
				return err
			}
		}
	}

	if o.ClientID != nil {

		// query param client_id
		var qrClientID string

		if o.ClientID != nil {
			qrClientID = *o.ClientID
		}
		qClientID := qrClientID
		if qClientID != "" {

			if err := r.SetQueryParam("client_id", qClientID); err != nil {
				return err
			}
		}
	}

	if o.EventAction != nil {

		// binding items for event_action
		joinedEventAction := o.bindParamEventAction(reg)

		// query array param event_action
		if err := r.SetQueryParam("event_action", joinedEventAction...); err != nil {
			return err
		}
	}

	if o.EventSubject != nil {

		// binding items for event_subject
		joinedEventSubject := o.bindParamEventSubject(reg)

		// query array param event_subject
		if err := r.SetQueryParam("event_subject", joinedEventSubject...); err != nil {
			return err
		}
	}

	if o.GroupID != nil {

		// query param group_id
		var qrGroupID string

		if o.GroupID != nil {
			qrGroupID = *o.GroupID
		}
		qGroupID := qrGroupID
		if qGroupID != "" {

			if err := r.SetQueryParam("group_id", qGroupID); err != nil {
				return err
			}
		}
	}

	if o.IdpID != nil {

		// query param idp_id
		var qrIdpID string

		if o.IdpID != nil {
			qrIdpID = *o.IdpID
		}
		qIdpID := qrIdpID
		if qIdpID != "" {

			if err := r.SetQueryParam("idp_id", qIdpID); err != nil {
				return err
			}
		}
	}

	if o.IdpMethod != nil {

		// query param idp_method
		var qrIdpMethod string

		if o.IdpMethod != nil {
			qrIdpMethod = *o.IdpMethod
		}
		qIdpMethod := qrIdpMethod
		if qIdpMethod != "" {

			if err := r.SetQueryParam("idp_method", qIdpMethod); err != nil {
				return err
			}
		}
	}

	if o.IdpSubject != nil {

		// query param idp_subject
		var qrIdpSubject string

		if o.IdpSubject != nil {
			qrIdpSubject = *o.IdpSubject
		}
		qIdpSubject := qrIdpSubject
		if qIdpSubject != "" {

			if err := r.SetQueryParam("idp_subject", qIdpSubject); err != nil {
				return err
			}
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if o.IP != nil {

		// query param ip
		var qrIP string

		if o.IP != nil {
			qrIP = *o.IP
		}
		qIP := qrIP
		if qIP != "" {

			if err := r.SetQueryParam("ip", qIP); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Order != nil {

		// query param order
		var qrOrder string

		if o.Order != nil {
			qrOrder = *o.Order
		}
		qOrder := qrOrder
		if qOrder != "" {

			if err := r.SetQueryParam("order", qOrder); err != nil {
				return err
			}
		}
	}

	if o.OrganizationID != nil {

		// query param organization_id
		var qrOrganizationID string

		if o.OrganizationID != nil {
			qrOrganizationID = *o.OrganizationID
		}
		qOrganizationID := qrOrganizationID
		if qOrganizationID != "" {

			if err := r.SetQueryParam("organization_id", qOrganizationID); err != nil {
				return err
			}
		}
	}

	if o.SessionID != nil {

		// query param session_id
		var qrSessionID string

		if o.SessionID != nil {
			qrSessionID = *o.SessionID
		}
		qSessionID := qrSessionID
		if qSessionID != "" {

			if err := r.SetQueryParam("session_id", qSessionID); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if o.Subject != nil {

		// query param subject
		var qrSubject string

		if o.Subject != nil {
			qrSubject = *o.Subject
		}
		qSubject := qrSubject
		if qSubject != "" {

			if err := r.SetQueryParam("subject", qSubject); err != nil {
				return err
			}
		}
	}

	if o.TimestampFrom != nil {

		// query param timestamp_from
		var qrTimestampFrom strfmt.DateTime

		if o.TimestampFrom != nil {
			qrTimestampFrom = *o.TimestampFrom
		}
		qTimestampFrom := qrTimestampFrom.String()
		if qTimestampFrom != "" {

			if err := r.SetQueryParam("timestamp_from", qTimestampFrom); err != nil {
				return err
			}
		}
	}

	if o.TimestampTo != nil {

		// query param timestamp_to
		var qrTimestampTo strfmt.DateTime

		if o.TimestampTo != nil {
			qrTimestampTo = *o.TimestampTo
		}
		qTimestampTo := qrTimestampTo.String()
		if qTimestampTo != "" {

			if err := r.SetQueryParam("timestamp_to", qTimestampTo); err != nil {
				return err
			}
		}
	}

	if o.UserID != nil {

		// query param user_id
		var qrUserID string

		if o.UserID != nil {
			qrUserID = *o.UserID
		}
		qUserID := qrUserID
		if qUserID != "" {

			if err := r.SetQueryParam("user_id", qUserID); err != nil {
				return err
			}
		}
	}

	if o.UserPoolID != nil {

		// query param user_pool_id
		var qrUserPoolID string

		if o.UserPoolID != nil {
			qrUserPoolID = *o.UserPoolID
		}
		qUserPoolID := qrUserPoolID
		if qUserPoolID != "" {

			if err := r.SetQueryParam("user_pool_id", qUserPoolID); err != nil {
				return err
			}
		}
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamListAuditEvents binds the parameter event_action
func (o *ListAuditEventsParams) bindParamEventAction(formats strfmt.Registry) []string {
	eventActionIR := o.EventAction

	var eventActionIC []string
	for _, eventActionIIR := range eventActionIR { // explode []string

		eventActionIIV := eventActionIIR // string as string
		eventActionIC = append(eventActionIC, eventActionIIV)
	}

	// items.CollectionFormat: ""
	eventActionIS := swag.JoinByFormat(eventActionIC, "")

	return eventActionIS
}

// bindParamListAuditEvents binds the parameter event_subject
func (o *ListAuditEventsParams) bindParamEventSubject(formats strfmt.Registry) []string {
	eventSubjectIR := o.EventSubject

	var eventSubjectIC []string
	for _, eventSubjectIIR := range eventSubjectIR { // explode []string

		eventSubjectIIV := eventSubjectIIR // string as string
		eventSubjectIC = append(eventSubjectIC, eventSubjectIIV)
	}

	// items.CollectionFormat: ""
	eventSubjectIS := swag.JoinByFormat(eventSubjectIC, "")

	return eventSubjectIS
}
