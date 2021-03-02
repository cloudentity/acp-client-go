// Code generated by go-swagger; DO NOT EDIT.

package logins

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

	"github.com/cloudentity/acp-client-go/models"
)

// NewRejectLoginRequestParams creates a new RejectLoginRequestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRejectLoginRequestParams() *RejectLoginRequestParams {
	return &RejectLoginRequestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRejectLoginRequestParamsWithTimeout creates a new RejectLoginRequestParams object
// with the ability to set a timeout on a request.
func NewRejectLoginRequestParamsWithTimeout(timeout time.Duration) *RejectLoginRequestParams {
	return &RejectLoginRequestParams{
		timeout: timeout,
	}
}

// NewRejectLoginRequestParamsWithContext creates a new RejectLoginRequestParams object
// with the ability to set a context for a request.
func NewRejectLoginRequestParamsWithContext(ctx context.Context) *RejectLoginRequestParams {
	return &RejectLoginRequestParams{
		Context: ctx,
	}
}

// NewRejectLoginRequestParamsWithHTTPClient creates a new RejectLoginRequestParams object
// with the ability to set a custom HTTPClient for a request.
func NewRejectLoginRequestParamsWithHTTPClient(client *http.Client) *RejectLoginRequestParams {
	return &RejectLoginRequestParams{
		HTTPClient: client,
	}
}

/* RejectLoginRequestParams contains all the parameters to send to the API endpoint
   for the reject login request operation.

   Typically these are written to a http.Request.
*/
type RejectLoginRequestParams struct {

	// RejectLogin.
	RejectLogin *models.RejectLogin

	// Login.
	LoginID string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the reject login request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectLoginRequestParams) WithDefaults() *RejectLoginRequestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the reject login request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectLoginRequestParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := RejectLoginRequestParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the reject login request params
func (o *RejectLoginRequestParams) WithTimeout(timeout time.Duration) *RejectLoginRequestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the reject login request params
func (o *RejectLoginRequestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the reject login request params
func (o *RejectLoginRequestParams) WithContext(ctx context.Context) *RejectLoginRequestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the reject login request params
func (o *RejectLoginRequestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the reject login request params
func (o *RejectLoginRequestParams) WithHTTPClient(client *http.Client) *RejectLoginRequestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the reject login request params
func (o *RejectLoginRequestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRejectLogin adds the rejectLogin to the reject login request params
func (o *RejectLoginRequestParams) WithRejectLogin(rejectLogin *models.RejectLogin) *RejectLoginRequestParams {
	o.SetRejectLogin(rejectLogin)
	return o
}

// SetRejectLogin adds the rejectLogin to the reject login request params
func (o *RejectLoginRequestParams) SetRejectLogin(rejectLogin *models.RejectLogin) {
	o.RejectLogin = rejectLogin
}

// WithLoginID adds the login to the reject login request params
func (o *RejectLoginRequestParams) WithLoginID(login string) *RejectLoginRequestParams {
	o.SetLoginID(login)
	return o
}

// SetLoginID adds the login to the reject login request params
func (o *RejectLoginRequestParams) SetLoginID(login string) {
	o.LoginID = login
}

// WithTid adds the tid to the reject login request params
func (o *RejectLoginRequestParams) WithTid(tid string) *RejectLoginRequestParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the reject login request params
func (o *RejectLoginRequestParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *RejectLoginRequestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.RejectLogin != nil {
		if err := r.SetBodyParam(o.RejectLogin); err != nil {
			return err
		}
	}

	// path param login
	if err := r.SetPathParam("login", o.LoginID); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
