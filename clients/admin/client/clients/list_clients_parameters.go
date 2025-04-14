// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewListClientsParams creates a new ListClientsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListClientsParams() *ListClientsParams {
	return &ListClientsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListClientsParamsWithTimeout creates a new ListClientsParams object
// with the ability to set a timeout on a request.
func NewListClientsParamsWithTimeout(timeout time.Duration) *ListClientsParams {
	return &ListClientsParams{
		timeout: timeout,
	}
}

// NewListClientsParamsWithContext creates a new ListClientsParams object
// with the ability to set a context for a request.
func NewListClientsParamsWithContext(ctx context.Context) *ListClientsParams {
	return &ListClientsParams{
		Context: ctx,
	}
}

// NewListClientsParamsWithHTTPClient creates a new ListClientsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListClientsParamsWithHTTPClient(client *http.Client) *ListClientsParams {
	return &ListClientsParams{
		HTTPClient: client,
	}
}

/*
ListClientsParams contains all the parameters to send to the API endpoint

	for the list clients operation.

	Typically these are written to a http.Request.
*/
type ListClientsParams struct {

	/* AfterClientID.

	     optional list clients after given id
	AfterClientID
	*/
	AfterClientID *string

	/* ApplicationTypes.

	     Optional application types
	ApplicationTypes
	*/
	ApplicationTypes *string

	/* BeforeClientID.

	     optional list clients before given id
	BeforeClientID
	*/
	BeforeClientID *string

	/* ClientTypes.

	   Optional client types (oauth2, saml)
	*/
	ClientTypes *string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Limit.

	     optional limit results
	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     optional order clients by given direction
	Order
	*/
	Order *string

	/* SearchPhrase.

	     Optional search phrase: client id OR client name substring
	SearchPhrase
	*/
	SearchPhrase *string

	/* Sort.

	     optional sort clients by given field, one of: name, client_id, issued_at
	Sort
	*/
	Sort *string

	/* Type.

	     Optional type, one of: internal, third_party
	Type
	*/
	Type *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsParams) WithDefaults() *ListClientsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsParams) SetDefaults() {
	var (
		limitDefault = int64(20)

		widDefault = string("default")
	)

	val := ListClientsParams{
		Limit: &limitDefault,
		Wid:   widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list clients params
func (o *ListClientsParams) WithTimeout(timeout time.Duration) *ListClientsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list clients params
func (o *ListClientsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list clients params
func (o *ListClientsParams) WithContext(ctx context.Context) *ListClientsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list clients params
func (o *ListClientsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list clients params
func (o *ListClientsParams) WithHTTPClient(client *http.Client) *ListClientsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list clients params
func (o *ListClientsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterClientID adds the afterClientID to the list clients params
func (o *ListClientsParams) WithAfterClientID(afterClientID *string) *ListClientsParams {
	o.SetAfterClientID(afterClientID)
	return o
}

// SetAfterClientID adds the afterClientId to the list clients params
func (o *ListClientsParams) SetAfterClientID(afterClientID *string) {
	o.AfterClientID = afterClientID
}

// WithApplicationTypes adds the applicationTypes to the list clients params
func (o *ListClientsParams) WithApplicationTypes(applicationTypes *string) *ListClientsParams {
	o.SetApplicationTypes(applicationTypes)
	return o
}

// SetApplicationTypes adds the applicationTypes to the list clients params
func (o *ListClientsParams) SetApplicationTypes(applicationTypes *string) {
	o.ApplicationTypes = applicationTypes
}

// WithBeforeClientID adds the beforeClientID to the list clients params
func (o *ListClientsParams) WithBeforeClientID(beforeClientID *string) *ListClientsParams {
	o.SetBeforeClientID(beforeClientID)
	return o
}

// SetBeforeClientID adds the beforeClientId to the list clients params
func (o *ListClientsParams) SetBeforeClientID(beforeClientID *string) {
	o.BeforeClientID = beforeClientID
}

// WithClientTypes adds the clientTypes to the list clients params
func (o *ListClientsParams) WithClientTypes(clientTypes *string) *ListClientsParams {
	o.SetClientTypes(clientTypes)
	return o
}

// SetClientTypes adds the clientTypes to the list clients params
func (o *ListClientsParams) SetClientTypes(clientTypes *string) {
	o.ClientTypes = clientTypes
}

// WithIfMatch adds the ifMatch to the list clients params
func (o *ListClientsParams) WithIfMatch(ifMatch *string) *ListClientsParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list clients params
func (o *ListClientsParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithLimit adds the limit to the list clients params
func (o *ListClientsParams) WithLimit(limit *int64) *ListClientsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list clients params
func (o *ListClientsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list clients params
func (o *ListClientsParams) WithOrder(order *string) *ListClientsParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list clients params
func (o *ListClientsParams) SetOrder(order *string) {
	o.Order = order
}

// WithSearchPhrase adds the searchPhrase to the list clients params
func (o *ListClientsParams) WithSearchPhrase(searchPhrase *string) *ListClientsParams {
	o.SetSearchPhrase(searchPhrase)
	return o
}

// SetSearchPhrase adds the searchPhrase to the list clients params
func (o *ListClientsParams) SetSearchPhrase(searchPhrase *string) {
	o.SearchPhrase = searchPhrase
}

// WithSort adds the sort to the list clients params
func (o *ListClientsParams) WithSort(sort *string) *ListClientsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list clients params
func (o *ListClientsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithType adds the typeVar to the list clients params
func (o *ListClientsParams) WithType(typeVar *string) *ListClientsParams {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the list clients params
func (o *ListClientsParams) SetType(typeVar *string) {
	o.Type = typeVar
}

// WithWid adds the wid to the list clients params
func (o *ListClientsParams) WithWid(wid string) *ListClientsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list clients params
func (o *ListClientsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListClientsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterClientID != nil {

		// query param after_client_id
		var qrAfterClientID string

		if o.AfterClientID != nil {
			qrAfterClientID = *o.AfterClientID
		}
		qAfterClientID := qrAfterClientID
		if qAfterClientID != "" {

			if err := r.SetQueryParam("after_client_id", qAfterClientID); err != nil {
				return err
			}
		}
	}

	if o.ApplicationTypes != nil {

		// query param application_types
		var qrApplicationTypes string

		if o.ApplicationTypes != nil {
			qrApplicationTypes = *o.ApplicationTypes
		}
		qApplicationTypes := qrApplicationTypes
		if qApplicationTypes != "" {

			if err := r.SetQueryParam("application_types", qApplicationTypes); err != nil {
				return err
			}
		}
	}

	if o.BeforeClientID != nil {

		// query param before_client_id
		var qrBeforeClientID string

		if o.BeforeClientID != nil {
			qrBeforeClientID = *o.BeforeClientID
		}
		qBeforeClientID := qrBeforeClientID
		if qBeforeClientID != "" {

			if err := r.SetQueryParam("before_client_id", qBeforeClientID); err != nil {
				return err
			}
		}
	}

	if o.ClientTypes != nil {

		// query param client_types
		var qrClientTypes string

		if o.ClientTypes != nil {
			qrClientTypes = *o.ClientTypes
		}
		qClientTypes := qrClientTypes
		if qClientTypes != "" {

			if err := r.SetQueryParam("client_types", qClientTypes); err != nil {
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

	if o.SearchPhrase != nil {

		// query param search_phrase
		var qrSearchPhrase string

		if o.SearchPhrase != nil {
			qrSearchPhrase = *o.SearchPhrase
		}
		qSearchPhrase := qrSearchPhrase
		if qSearchPhrase != "" {

			if err := r.SetQueryParam("search_phrase", qSearchPhrase); err != nil {
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

	if o.Type != nil {

		// query param type
		var qrType string

		if o.Type != nil {
			qrType = *o.Type
		}
		qType := qrType
		if qType != "" {

			if err := r.SetQueryParam("type", qType); err != nil {
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
