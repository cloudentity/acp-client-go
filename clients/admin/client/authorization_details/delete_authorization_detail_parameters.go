// Code generated by go-swagger; DO NOT EDIT.

package authorization_details

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
)

// NewDeleteAuthorizationDetailParams creates a new DeleteAuthorizationDetailParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteAuthorizationDetailParams() *DeleteAuthorizationDetailParams {
	return &DeleteAuthorizationDetailParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteAuthorizationDetailParamsWithTimeout creates a new DeleteAuthorizationDetailParams object
// with the ability to set a timeout on a request.
func NewDeleteAuthorizationDetailParamsWithTimeout(timeout time.Duration) *DeleteAuthorizationDetailParams {
	return &DeleteAuthorizationDetailParams{
		timeout: timeout,
	}
}

// NewDeleteAuthorizationDetailParamsWithContext creates a new DeleteAuthorizationDetailParams object
// with the ability to set a context for a request.
func NewDeleteAuthorizationDetailParamsWithContext(ctx context.Context) *DeleteAuthorizationDetailParams {
	return &DeleteAuthorizationDetailParams{
		Context: ctx,
	}
}

// NewDeleteAuthorizationDetailParamsWithHTTPClient creates a new DeleteAuthorizationDetailParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteAuthorizationDetailParamsWithHTTPClient(client *http.Client) *DeleteAuthorizationDetailParams {
	return &DeleteAuthorizationDetailParams{
		HTTPClient: client,
	}
}

/*
DeleteAuthorizationDetailParams contains all the parameters to send to the API endpoint

	for the delete authorization detail operation.

	Typically these are written to a http.Request.
*/
type DeleteAuthorizationDetailParams struct {

	/* AuthorizationDetailID.

	   AuthorizationDetail ID
	*/
	AuthorizationDetailID string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete authorization detail params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteAuthorizationDetailParams) WithDefaults() *DeleteAuthorizationDetailParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete authorization detail params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteAuthorizationDetailParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) WithTimeout(timeout time.Duration) *DeleteAuthorizationDetailParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) WithContext(ctx context.Context) *DeleteAuthorizationDetailParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) WithHTTPClient(client *http.Client) *DeleteAuthorizationDetailParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorizationDetailID adds the authorizationDetailID to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) WithAuthorizationDetailID(authorizationDetailID string) *DeleteAuthorizationDetailParams {
	o.SetAuthorizationDetailID(authorizationDetailID)
	return o
}

// SetAuthorizationDetailID adds the authorizationDetailId to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) SetAuthorizationDetailID(authorizationDetailID string) {
	o.AuthorizationDetailID = authorizationDetailID
}

// WithIfMatch adds the ifMatch to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) WithIfMatch(ifMatch *string) *DeleteAuthorizationDetailParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the delete authorization detail params
func (o *DeleteAuthorizationDetailParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteAuthorizationDetailParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param authorizationDetailID
	if err := r.SetPathParam("authorizationDetailID", o.AuthorizationDetailID); err != nil {
		return err
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
