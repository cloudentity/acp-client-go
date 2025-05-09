// Code generated by go-swagger; DO NOT EDIT.

package roles

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

// NewListUserRolesParams creates a new ListUserRolesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListUserRolesParams() *ListUserRolesParams {
	return &ListUserRolesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListUserRolesParamsWithTimeout creates a new ListUserRolesParams object
// with the ability to set a timeout on a request.
func NewListUserRolesParamsWithTimeout(timeout time.Duration) *ListUserRolesParams {
	return &ListUserRolesParams{
		timeout: timeout,
	}
}

// NewListUserRolesParamsWithContext creates a new ListUserRolesParams object
// with the ability to set a context for a request.
func NewListUserRolesParamsWithContext(ctx context.Context) *ListUserRolesParams {
	return &ListUserRolesParams{
		Context: ctx,
	}
}

// NewListUserRolesParamsWithHTTPClient creates a new ListUserRolesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListUserRolesParamsWithHTTPClient(client *http.Client) *ListUserRolesParams {
	return &ListUserRolesParams{
		HTTPClient: client,
	}
}

/*
ListUserRolesParams contains all the parameters to send to the API endpoint

	for the list user roles operation.

	Typically these are written to a http.Request.
*/
type ListUserRolesParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* IPID.

	   Identity pool id

	   Default: "default"
	*/
	IPID string

	/* UserID.

	   User id

	   Format: userID
	   Default: "default"
	*/
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list user roles params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUserRolesParams) WithDefaults() *ListUserRolesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list user roles params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUserRolesParams) SetDefaults() {
	var (
		iPIDDefault = string("default")

		userIDDefault = string("default")
	)

	val := ListUserRolesParams{
		IPID:   iPIDDefault,
		UserID: userIDDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list user roles params
func (o *ListUserRolesParams) WithTimeout(timeout time.Duration) *ListUserRolesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list user roles params
func (o *ListUserRolesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list user roles params
func (o *ListUserRolesParams) WithContext(ctx context.Context) *ListUserRolesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list user roles params
func (o *ListUserRolesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list user roles params
func (o *ListUserRolesParams) WithHTTPClient(client *http.Client) *ListUserRolesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list user roles params
func (o *ListUserRolesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the list user roles params
func (o *ListUserRolesParams) WithIfMatch(ifMatch *string) *ListUserRolesParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list user roles params
func (o *ListUserRolesParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the list user roles params
func (o *ListUserRolesParams) WithIPID(iPID string) *ListUserRolesParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the list user roles params
func (o *ListUserRolesParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the list user roles params
func (o *ListUserRolesParams) WithUserID(userID string) *ListUserRolesParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the list user roles params
func (o *ListUserRolesParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *ListUserRolesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
