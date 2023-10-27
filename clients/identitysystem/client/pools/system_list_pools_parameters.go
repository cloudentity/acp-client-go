// Code generated by go-swagger; DO NOT EDIT.

package pools

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

// NewSystemListPoolsParams creates a new SystemListPoolsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSystemListPoolsParams() *SystemListPoolsParams {
	return &SystemListPoolsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSystemListPoolsParamsWithTimeout creates a new SystemListPoolsParams object
// with the ability to set a timeout on a request.
func NewSystemListPoolsParamsWithTimeout(timeout time.Duration) *SystemListPoolsParams {
	return &SystemListPoolsParams{
		timeout: timeout,
	}
}

// NewSystemListPoolsParamsWithContext creates a new SystemListPoolsParams object
// with the ability to set a context for a request.
func NewSystemListPoolsParamsWithContext(ctx context.Context) *SystemListPoolsParams {
	return &SystemListPoolsParams{
		Context: ctx,
	}
}

// NewSystemListPoolsParamsWithHTTPClient creates a new SystemListPoolsParams object
// with the ability to set a custom HTTPClient for a request.
func NewSystemListPoolsParamsWithHTTPClient(client *http.Client) *SystemListPoolsParams {
	return &SystemListPoolsParams{
		HTTPClient: client,
	}
}

/*
SystemListPoolsParams contains all the parameters to send to the API endpoint

	for the system list pools operation.

	Typically these are written to a http.Request.
*/
type SystemListPoolsParams struct {

	/* AfterPoolID.

	     An identity pool identifier.

	Use it to navigate through the request pagination when the number of identity pools is greater than the
	`limit` set for results in the response.

	With `after_pool_id`, the list you obtain starts from the subsequent identity pool after the specified one. Also,
	the response depends on the `sort` and `order` parameters, if any are passed.

	AfterPoolID
	*/
	AfterPoolID *string

	/* BeforePoolID.

	     An identity pool identifier.

	Use it to navigate through the request pagination when the number of identity pools is greater than the
	`limit` set for the results in the response.

	With `before_pool_id`, the list you obtain comprises identity pools up to the specified one. The specified
	identity pool isn't included. Also, the response depends on the `sort` and `order` parameters, if any are
	passed.

	BeforePoolID
	*/
	BeforePoolID *string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Limit.

	     Limit the number of results returned in the response.

	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     Set the order of results returned in the response. Input: `acs`, `desc`.

	Order
	*/
	Order *string

	/* SearchPhrase.

	     A search substring. Use the identity pool identifier or name as its value.

	SearchPhrase
	*/
	SearchPhrase *string

	/* Sort.

	     Sort results returned in the response by `name` or `id`.

	Sort
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the system list pools params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemListPoolsParams) WithDefaults() *SystemListPoolsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the system list pools params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemListPoolsParams) SetDefaults() {
	var (
		limitDefault = int64(20)
	)

	val := SystemListPoolsParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the system list pools params
func (o *SystemListPoolsParams) WithTimeout(timeout time.Duration) *SystemListPoolsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the system list pools params
func (o *SystemListPoolsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the system list pools params
func (o *SystemListPoolsParams) WithContext(ctx context.Context) *SystemListPoolsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the system list pools params
func (o *SystemListPoolsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the system list pools params
func (o *SystemListPoolsParams) WithHTTPClient(client *http.Client) *SystemListPoolsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the system list pools params
func (o *SystemListPoolsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterPoolID adds the afterPoolID to the system list pools params
func (o *SystemListPoolsParams) WithAfterPoolID(afterPoolID *string) *SystemListPoolsParams {
	o.SetAfterPoolID(afterPoolID)
	return o
}

// SetAfterPoolID adds the afterPoolId to the system list pools params
func (o *SystemListPoolsParams) SetAfterPoolID(afterPoolID *string) {
	o.AfterPoolID = afterPoolID
}

// WithBeforePoolID adds the beforePoolID to the system list pools params
func (o *SystemListPoolsParams) WithBeforePoolID(beforePoolID *string) *SystemListPoolsParams {
	o.SetBeforePoolID(beforePoolID)
	return o
}

// SetBeforePoolID adds the beforePoolId to the system list pools params
func (o *SystemListPoolsParams) SetBeforePoolID(beforePoolID *string) {
	o.BeforePoolID = beforePoolID
}

// WithIfMatch adds the ifMatch to the system list pools params
func (o *SystemListPoolsParams) WithIfMatch(ifMatch *string) *SystemListPoolsParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the system list pools params
func (o *SystemListPoolsParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithLimit adds the limit to the system list pools params
func (o *SystemListPoolsParams) WithLimit(limit *int64) *SystemListPoolsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the system list pools params
func (o *SystemListPoolsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the system list pools params
func (o *SystemListPoolsParams) WithOrder(order *string) *SystemListPoolsParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the system list pools params
func (o *SystemListPoolsParams) SetOrder(order *string) {
	o.Order = order
}

// WithSearchPhrase adds the searchPhrase to the system list pools params
func (o *SystemListPoolsParams) WithSearchPhrase(searchPhrase *string) *SystemListPoolsParams {
	o.SetSearchPhrase(searchPhrase)
	return o
}

// SetSearchPhrase adds the searchPhrase to the system list pools params
func (o *SystemListPoolsParams) SetSearchPhrase(searchPhrase *string) {
	o.SearchPhrase = searchPhrase
}

// WithSort adds the sort to the system list pools params
func (o *SystemListPoolsParams) WithSort(sort *string) *SystemListPoolsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the system list pools params
func (o *SystemListPoolsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *SystemListPoolsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterPoolID != nil {

		// query param after_pool_id
		var qrAfterPoolID string

		if o.AfterPoolID != nil {
			qrAfterPoolID = *o.AfterPoolID
		}
		qAfterPoolID := qrAfterPoolID
		if qAfterPoolID != "" {

			if err := r.SetQueryParam("after_pool_id", qAfterPoolID); err != nil {
				return err
			}
		}
	}

	if o.BeforePoolID != nil {

		// query param before_pool_id
		var qrBeforePoolID string

		if o.BeforePoolID != nil {
			qrBeforePoolID = *o.BeforePoolID
		}
		qBeforePoolID := qrBeforePoolID
		if qBeforePoolID != "" {

			if err := r.SetQueryParam("before_pool_id", qBeforePoolID); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
