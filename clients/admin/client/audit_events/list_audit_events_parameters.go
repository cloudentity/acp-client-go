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

	/* AfterEventID.

	     optional list audit events after a given event id
	AfterEventID
	*/
	AfterEventID *string

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

	     Optional list of event types, one of: authorized unauthorized created updated deleted requested accepted rejected issued denied granted attempted failed sent not_sent revoked
	EventType
	*/
	EventAction []string

	/* EventSubject.

	     Optional list of event subjects, one of: request client gateway_request policy consent authorization_code recovery login access_token scopes otp gateway_policy user credential dcr role jit
	EventSubject
	*/
	EventSubject []string

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

// WithAfterEventID adds the afterEventID to the list audit events params
func (o *ListAuditEventsParams) WithAfterEventID(afterEventID *string) *ListAuditEventsParams {
	o.SetAfterEventID(afterEventID)
	return o
}

// SetAfterEventID adds the afterEventId to the list audit events params
func (o *ListAuditEventsParams) SetAfterEventID(afterEventID *string) {
	o.AfterEventID = afterEventID
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
