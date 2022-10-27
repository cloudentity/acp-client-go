// Code generated by go-swagger; DO NOT EDIT.

package services

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

// NewListServicesParams creates a new ListServicesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListServicesParams() *ListServicesParams {
	return &ListServicesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListServicesParamsWithTimeout creates a new ListServicesParams object
// with the ability to set a timeout on a request.
func NewListServicesParamsWithTimeout(timeout time.Duration) *ListServicesParams {
	return &ListServicesParams{
		timeout: timeout,
	}
}

// NewListServicesParamsWithContext creates a new ListServicesParams object
// with the ability to set a context for a request.
func NewListServicesParamsWithContext(ctx context.Context) *ListServicesParams {
	return &ListServicesParams{
		Context: ctx,
	}
}

// NewListServicesParamsWithHTTPClient creates a new ListServicesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListServicesParamsWithHTTPClient(client *http.Client) *ListServicesParams {
	return &ListServicesParams{
		HTTPClient: client,
	}
}

/*
ListServicesParams contains all the parameters to send to the API endpoint

	for the list services operation.

	Typically these are written to a http.Request.
*/
type ListServicesParams struct {

	/* AfterServiceID.

	     optional list services after given id
	AfterServiceID
	*/
	AfterServiceID *string

	/* BeforeServiceID.

	     optional list services before given id
	BeforeServiceID
	*/
	BeforeServiceID *string

	/* Limit.

	     optional limit results
	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     optional order services by given direction
	Order
	*/
	Order *string

	/* SearchPhrase.

	     Optional search phrase: service id OR service name substring (case insensitive)
	SearchPhrase
	*/
	SearchPhrase *string

	/* ServiceTypes.

	   comma separated service types that are to be filtered out

	   Default: "user,oauth2,oidc,system,openbanking"
	*/
	ServiceTypes *string

	/* Sort.

	     optional sort services by given field
	Sort
	*/
	Sort *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list services params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListServicesParams) WithDefaults() *ListServicesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list services params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListServicesParams) SetDefaults() {
	var (
		limitDefault = int64(20)

		serviceTypesDefault = string("user,oauth2,oidc,system,openbanking")

		widDefault = string("default")
	)

	val := ListServicesParams{
		Limit:        &limitDefault,
		ServiceTypes: &serviceTypesDefault,
		Wid:          widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list services params
func (o *ListServicesParams) WithTimeout(timeout time.Duration) *ListServicesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list services params
func (o *ListServicesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list services params
func (o *ListServicesParams) WithContext(ctx context.Context) *ListServicesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list services params
func (o *ListServicesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list services params
func (o *ListServicesParams) WithHTTPClient(client *http.Client) *ListServicesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list services params
func (o *ListServicesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAfterServiceID adds the afterServiceID to the list services params
func (o *ListServicesParams) WithAfterServiceID(afterServiceID *string) *ListServicesParams {
	o.SetAfterServiceID(afterServiceID)
	return o
}

// SetAfterServiceID adds the afterServiceId to the list services params
func (o *ListServicesParams) SetAfterServiceID(afterServiceID *string) {
	o.AfterServiceID = afterServiceID
}

// WithBeforeServiceID adds the beforeServiceID to the list services params
func (o *ListServicesParams) WithBeforeServiceID(beforeServiceID *string) *ListServicesParams {
	o.SetBeforeServiceID(beforeServiceID)
	return o
}

// SetBeforeServiceID adds the beforeServiceId to the list services params
func (o *ListServicesParams) SetBeforeServiceID(beforeServiceID *string) {
	o.BeforeServiceID = beforeServiceID
}

// WithLimit adds the limit to the list services params
func (o *ListServicesParams) WithLimit(limit *int64) *ListServicesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list services params
func (o *ListServicesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the list services params
func (o *ListServicesParams) WithOrder(order *string) *ListServicesParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the list services params
func (o *ListServicesParams) SetOrder(order *string) {
	o.Order = order
}

// WithSearchPhrase adds the searchPhrase to the list services params
func (o *ListServicesParams) WithSearchPhrase(searchPhrase *string) *ListServicesParams {
	o.SetSearchPhrase(searchPhrase)
	return o
}

// SetSearchPhrase adds the searchPhrase to the list services params
func (o *ListServicesParams) SetSearchPhrase(searchPhrase *string) {
	o.SearchPhrase = searchPhrase
}

// WithServiceTypes adds the serviceTypes to the list services params
func (o *ListServicesParams) WithServiceTypes(serviceTypes *string) *ListServicesParams {
	o.SetServiceTypes(serviceTypes)
	return o
}

// SetServiceTypes adds the serviceTypes to the list services params
func (o *ListServicesParams) SetServiceTypes(serviceTypes *string) {
	o.ServiceTypes = serviceTypes
}

// WithSort adds the sort to the list services params
func (o *ListServicesParams) WithSort(sort *string) *ListServicesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the list services params
func (o *ListServicesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithWid adds the wid to the list services params
func (o *ListServicesParams) WithWid(wid string) *ListServicesParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list services params
func (o *ListServicesParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListServicesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AfterServiceID != nil {

		// query param after_service_id
		var qrAfterServiceID string

		if o.AfterServiceID != nil {
			qrAfterServiceID = *o.AfterServiceID
		}
		qAfterServiceID := qrAfterServiceID
		if qAfterServiceID != "" {

			if err := r.SetQueryParam("after_service_id", qAfterServiceID); err != nil {
				return err
			}
		}
	}

	if o.BeforeServiceID != nil {

		// query param before_service_id
		var qrBeforeServiceID string

		if o.BeforeServiceID != nil {
			qrBeforeServiceID = *o.BeforeServiceID
		}
		qBeforeServiceID := qrBeforeServiceID
		if qBeforeServiceID != "" {

			if err := r.SetQueryParam("before_service_id", qBeforeServiceID); err != nil {
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

	if o.ServiceTypes != nil {

		// query param service_types
		var qrServiceTypes string

		if o.ServiceTypes != nil {
			qrServiceTypes = *o.ServiceTypes
		}
		qServiceTypes := qrServiceTypes
		if qServiceTypes != "" {

			if err := r.SetQueryParam("service_types", qServiceTypes); err != nil {
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

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
