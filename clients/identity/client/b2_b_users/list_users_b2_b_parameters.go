// Code generated by go-swagger; DO NOT EDIT.

package b2_b_users

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

// NewListUsersB2BParams creates a new ListUsersB2BParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListUsersB2BParams() *ListUsersB2BParams {
	return &ListUsersB2BParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListUsersB2BParamsWithTimeout creates a new ListUsersB2BParams object
// with the ability to set a timeout on a request.
func NewListUsersB2BParamsWithTimeout(timeout time.Duration) *ListUsersB2BParams {
	return &ListUsersB2BParams{
		timeout: timeout,
	}
}

// NewListUsersB2BParamsWithContext creates a new ListUsersB2BParams object
// with the ability to set a context for a request.
func NewListUsersB2BParamsWithContext(ctx context.Context) *ListUsersB2BParams {
	return &ListUsersB2BParams{
		Context: ctx,
	}
}

// NewListUsersB2BParamsWithHTTPClient creates a new ListUsersB2BParams object
// with the ability to set a custom HTTPClient for a request.
func NewListUsersB2BParamsWithHTTPClient(client *http.Client) *ListUsersB2BParams {
	return &ListUsersB2BParams{
		HTTPClient: client,
	}
}

/*
ListUsersB2BParams contains all the parameters to send to the API endpoint

	for the list users b2 b operation.

	Typically these are written to a http.Request.
*/
type ListUsersB2BParams struct {

	/* AfterUserID.

	     optional list users after given id
	AfterUserID
	*/
	AfterUserID *string

	/* BeforeUserID.

	     optional list users before given id
	BeforeUserID
	*/
	BeforeUserID *string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

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

	/* Query.

	     optional query filter
	query is in json format like {"user_key":"john"} - parameter must be url-encoded
	supported parameters
	`user_key` - limits user set to users that has identifier starting or ending with provided user_key or has verified address starting or ending with provided user_key or their ID is equal to provided user_key
	`payload` - limits user set to users with payload matches provided metadata - for simple values it does exact match, for arrays it does `contain`
	`metadata` - limits user set to users with metadata matches provided metadata - for simple values it does exact match, for arrays it does `contain`
	if multiple parameters provided it does logical AND between the results so users must match ALL parameters
	*/
	Query *string

	/* Sort.

	     optional sort clients by given field
	Sort
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list users b2 b params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUsersB2BParams) WithDefaults() *ListUsersB2BParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list users b2 b params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUsersB2BParams) SetDefaults() {
	var (
		limitDefault = int64(20)
	)

	val := ListUsersB2BParams{
		Limit: &limitDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list users b2 b params
func (o *ListUsersB2BParams) WithTimeout(timeout time.Duration) *ListUsersB2BParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list users b2 b params
func (o *ListUsersB2BParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list users b2 b params
func (o *ListUsersB2BParams) WithContext(ctx context.Context) *ListUsersB2BParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list users b2 b params
func (o *ListUsersB2BParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list users b2 b params
func (o *ListUsersB2BParams) WithHTTPClient(client *http.Client) *ListUsersB2BParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list users b2 b params
func (o *ListUsersB2BParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterUserID adds the afterUserID to the list users b2 b params
func (o *ListUsersB2BParams) WithAfterUserID(afterUserID *string) *ListUsersB2BParams {
	o.SetAfterUserID(afterUserID)
	return o
}

// SetAfterUserID adds the afterUserId to the list users b2 b params
func (o *ListUsersB2BParams) SetAfterUserID(afterUserID *string) {
	o.AfterUserID = afterUserID
}

// WithBeforeUserID adds the beforeUserID to the list users b2 b params
func (o *ListUsersB2BParams) WithBeforeUserID(beforeUserID *string) *ListUsersB2BParams {
	o.SetBeforeUserID(beforeUserID)
	return o
}

// SetBeforeUserID adds the beforeUserId to the list users b2 b params
func (o *ListUsersB2BParams) SetBeforeUserID(beforeUserID *string) {
	o.BeforeUserID = beforeUserID
}

// WithIfMatch adds the ifMatch to the list users b2 b params
func (o *ListUsersB2BParams) WithIfMatch(ifMatch *string) *ListUsersB2BParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list users b2 b params
func (o *ListUsersB2BParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the list users b2 b params
func (o *ListUsersB2BParams) WithIPID(iPID string) *ListUsersB2BParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the list users b2 b params
func (o *ListUsersB2BParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithLimit adds the limit to the list users b2 b params
func (o *ListUsersB2BParams) WithLimit(limit *int64) *ListUsersB2BParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list users b2 b params
func (o *ListUsersB2BParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list users b2 b params
func (o *ListUsersB2BParams) WithOrder(order *string) *ListUsersB2BParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list users b2 b params
func (o *ListUsersB2BParams) SetOrder(order *string) {
	o.Order = order
}

// WithQuery adds the query to the list users b2 b params
func (o *ListUsersB2BParams) WithQuery(query *string) *ListUsersB2BParams {
	o.SetQuery(query)
	return o
}

// SetQuery adds the query to the list users b2 b params
func (o *ListUsersB2BParams) SetQuery(query *string) {
	o.Query = query
}

// WithSort adds the sort to the list users b2 b params
func (o *ListUsersB2BParams) WithSort(sort *string) *ListUsersB2BParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list users b2 b params
func (o *ListUsersB2BParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *ListUsersB2BParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterUserID != nil {

		// query param after_user_id
		var qrAfterUserID string

		if o.AfterUserID != nil {
			qrAfterUserID = *o.AfterUserID
		}
		qAfterUserID := qrAfterUserID
		if qAfterUserID != "" {

			if err := r.SetQueryParam("after_user_id", qAfterUserID); err != nil {
				return err
			}
		}
	}

	if o.BeforeUserID != nil {

		// query param before_user_id
		var qrBeforeUserID string

		if o.BeforeUserID != nil {
			qrBeforeUserID = *o.BeforeUserID
		}
		qBeforeUserID := qrBeforeUserID
		if qBeforeUserID != "" {

			if err := r.SetQueryParam("before_user_id", qBeforeUserID); err != nil {
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

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
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

	if o.Query != nil {

		// query param query
		var qrQuery string

		if o.Query != nil {
			qrQuery = *o.Query
		}
		qQuery := qrQuery
		if qQuery != "" {

			if err := r.SetQueryParam("query", qQuery); err != nil {
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
