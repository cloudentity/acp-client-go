// Code generated by go-swagger; DO NOT EDIT.

package servers

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

// NewListAuthorizationServersParams creates a new ListAuthorizationServersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListAuthorizationServersParams() *ListAuthorizationServersParams {
	return &ListAuthorizationServersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListAuthorizationServersParamsWithTimeout creates a new ListAuthorizationServersParams object
// with the ability to set a timeout on a request.
func NewListAuthorizationServersParamsWithTimeout(timeout time.Duration) *ListAuthorizationServersParams {
	return &ListAuthorizationServersParams{
		timeout: timeout,
	}
}

// NewListAuthorizationServersParamsWithContext creates a new ListAuthorizationServersParams object
// with the ability to set a context for a request.
func NewListAuthorizationServersParamsWithContext(ctx context.Context) *ListAuthorizationServersParams {
	return &ListAuthorizationServersParams{
		Context: ctx,
	}
}

// NewListAuthorizationServersParamsWithHTTPClient creates a new ListAuthorizationServersParams object
// with the ability to set a custom HTTPClient for a request.
func NewListAuthorizationServersParamsWithHTTPClient(client *http.Client) *ListAuthorizationServersParams {
	return &ListAuthorizationServersParams{
		HTTPClient: client,
	}
}

/*
ListAuthorizationServersParams contains all the parameters to send to the API endpoint

	for the list authorization servers operation.

	Typically these are written to a http.Request.
*/
type ListAuthorizationServersParams struct {

	/* AfterServerID.

	     optional list servers after given id
	AfterServerID
	*/
	AfterServerID *string

	/* BeforeServerID.

	     optional list servers before given id
	BeforeServerID
	*/
	BeforeServerID *string

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

	     optional order servers by given direction
	Order
	*/
	Order *string

	/* SearchPhrase.

	     Optional search phrase: server id OR server name substring (case insensitive)
	SearchPhrase
	*/
	SearchPhrase *string

	/* ServerTypes.

	   comma separated server types that are to be filtered out

	   Default: "admin,developer,system,regular,organization"
	*/
	ServerTypes *string

	/* Sort.

	     optional sort servers by given field
	Sort
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list authorization servers params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuthorizationServersParams) WithDefaults() *ListAuthorizationServersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list authorization servers params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuthorizationServersParams) SetDefaults() {
	var (
		limitDefault = int64(20)

		serverTypesDefault = string("admin,developer,system,regular,organization")
	)

	val := ListAuthorizationServersParams{
		Limit:       &limitDefault,
		ServerTypes: &serverTypesDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list authorization servers params
func (o *ListAuthorizationServersParams) WithTimeout(timeout time.Duration) *ListAuthorizationServersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list authorization servers params
func (o *ListAuthorizationServersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list authorization servers params
func (o *ListAuthorizationServersParams) WithContext(ctx context.Context) *ListAuthorizationServersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list authorization servers params
func (o *ListAuthorizationServersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list authorization servers params
func (o *ListAuthorizationServersParams) WithHTTPClient(client *http.Client) *ListAuthorizationServersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list authorization servers params
func (o *ListAuthorizationServersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterServerID adds the afterServerID to the list authorization servers params
func (o *ListAuthorizationServersParams) WithAfterServerID(afterServerID *string) *ListAuthorizationServersParams {
	o.SetAfterServerID(afterServerID)
	return o
}

// SetAfterServerID adds the afterServerId to the list authorization servers params
func (o *ListAuthorizationServersParams) SetAfterServerID(afterServerID *string) {
	o.AfterServerID = afterServerID
}

// WithBeforeServerID adds the beforeServerID to the list authorization servers params
func (o *ListAuthorizationServersParams) WithBeforeServerID(beforeServerID *string) *ListAuthorizationServersParams {
	o.SetBeforeServerID(beforeServerID)
	return o
}

// SetBeforeServerID adds the beforeServerId to the list authorization servers params
func (o *ListAuthorizationServersParams) SetBeforeServerID(beforeServerID *string) {
	o.BeforeServerID = beforeServerID
}

// WithIfMatch adds the ifMatch to the list authorization servers params
func (o *ListAuthorizationServersParams) WithIfMatch(ifMatch *string) *ListAuthorizationServersParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list authorization servers params
func (o *ListAuthorizationServersParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithLimit adds the limit to the list authorization servers params
func (o *ListAuthorizationServersParams) WithLimit(limit *int64) *ListAuthorizationServersParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list authorization servers params
func (o *ListAuthorizationServersParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list authorization servers params
func (o *ListAuthorizationServersParams) WithOrder(order *string) *ListAuthorizationServersParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list authorization servers params
func (o *ListAuthorizationServersParams) SetOrder(order *string) {
	o.Order = order
}

// WithSearchPhrase adds the searchPhrase to the list authorization servers params
func (o *ListAuthorizationServersParams) WithSearchPhrase(searchPhrase *string) *ListAuthorizationServersParams {
	o.SetSearchPhrase(searchPhrase)
	return o
}

// SetSearchPhrase adds the searchPhrase to the list authorization servers params
func (o *ListAuthorizationServersParams) SetSearchPhrase(searchPhrase *string) {
	o.SearchPhrase = searchPhrase
}

// WithServerTypes adds the serverTypes to the list authorization servers params
func (o *ListAuthorizationServersParams) WithServerTypes(serverTypes *string) *ListAuthorizationServersParams {
	o.SetServerTypes(serverTypes)
	return o
}

// SetServerTypes adds the serverTypes to the list authorization servers params
func (o *ListAuthorizationServersParams) SetServerTypes(serverTypes *string) {
	o.ServerTypes = serverTypes
}

// WithSort adds the sort to the list authorization servers params
func (o *ListAuthorizationServersParams) WithSort(sort *string) *ListAuthorizationServersParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list authorization servers params
func (o *ListAuthorizationServersParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *ListAuthorizationServersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterServerID != nil {

		// query param after_server_id
		var qrAfterServerID string

		if o.AfterServerID != nil {
			qrAfterServerID = *o.AfterServerID
		}
		qAfterServerID := qrAfterServerID
		if qAfterServerID != "" {

			if err := r.SetQueryParam("after_server_id", qAfterServerID); err != nil {
				return err
			}
		}
	}

	if o.BeforeServerID != nil {

		// query param before_server_id
		var qrBeforeServerID string

		if o.BeforeServerID != nil {
			qrBeforeServerID = *o.BeforeServerID
		}
		qBeforeServerID := qrBeforeServerID
		if qBeforeServerID != "" {

			if err := r.SetQueryParam("before_server_id", qBeforeServerID); err != nil {
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

	if o.ServerTypes != nil {

		// query param server_types
		var qrServerTypes string

		if o.ServerTypes != nil {
			qrServerTypes = *o.ServerTypes
		}
		qServerTypes := qrServerTypes
		if qServerTypes != "" {

			if err := r.SetQueryParam("server_types", qServerTypes); err != nil {
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
