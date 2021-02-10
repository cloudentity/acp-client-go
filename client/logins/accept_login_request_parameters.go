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

// NewAcceptLoginRequestParams creates a new AcceptLoginRequestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAcceptLoginRequestParams() *AcceptLoginRequestParams {
	return &AcceptLoginRequestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAcceptLoginRequestParamsWithTimeout creates a new AcceptLoginRequestParams object
// with the ability to set a timeout on a request.
func NewAcceptLoginRequestParamsWithTimeout(timeout time.Duration) *AcceptLoginRequestParams {
	return &AcceptLoginRequestParams{
		timeout: timeout,
	}
}

// NewAcceptLoginRequestParamsWithContext creates a new AcceptLoginRequestParams object
// with the ability to set a context for a request.
func NewAcceptLoginRequestParamsWithContext(ctx context.Context) *AcceptLoginRequestParams {
	return &AcceptLoginRequestParams{
		Context: ctx,
	}
}

// NewAcceptLoginRequestParamsWithHTTPClient creates a new AcceptLoginRequestParams object
// with the ability to set a custom HTTPClient for a request.
func NewAcceptLoginRequestParamsWithHTTPClient(client *http.Client) *AcceptLoginRequestParams {
	return &AcceptLoginRequestParams{
		HTTPClient: client,
	}
}

/* AcceptLoginRequestParams contains all the parameters to send to the API endpoint
   for the accept login request operation.

   Typically these are written to a http.Request.
*/
type AcceptLoginRequestParams struct {

	// AcceptLogin.
	AcceptLogin *models.AcceptLogin

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

// WithDefaults hydrates default values in the accept login request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptLoginRequestParams) WithDefaults() *AcceptLoginRequestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the accept login request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptLoginRequestParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := AcceptLoginRequestParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the accept login request params
func (o *AcceptLoginRequestParams) WithTimeout(timeout time.Duration) *AcceptLoginRequestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the accept login request params
func (o *AcceptLoginRequestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the accept login request params
func (o *AcceptLoginRequestParams) WithContext(ctx context.Context) *AcceptLoginRequestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the accept login request params
func (o *AcceptLoginRequestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the accept login request params
func (o *AcceptLoginRequestParams) WithHTTPClient(client *http.Client) *AcceptLoginRequestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the accept login request params
func (o *AcceptLoginRequestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcceptLogin adds the acceptLogin to the accept login request params
func (o *AcceptLoginRequestParams) WithAcceptLogin(acceptLogin *models.AcceptLogin) *AcceptLoginRequestParams {
	o.SetAcceptLogin(acceptLogin)
	return o
}

// SetAcceptLogin adds the acceptLogin to the accept login request params
func (o *AcceptLoginRequestParams) SetAcceptLogin(acceptLogin *models.AcceptLogin) {
	o.AcceptLogin = acceptLogin
}

// WithLoginID adds the login to the accept login request params
func (o *AcceptLoginRequestParams) WithLoginID(login string) *AcceptLoginRequestParams {
	o.SetLoginID(login)
	return o
}

// SetLoginID adds the login to the accept login request params
func (o *AcceptLoginRequestParams) SetLoginID(login string) {
	o.LoginID = login
}

// WithTid adds the tid to the accept login request params
func (o *AcceptLoginRequestParams) WithTid(tid string) *AcceptLoginRequestParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the accept login request params
func (o *AcceptLoginRequestParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *AcceptLoginRequestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AcceptLogin != nil {
		if err := r.SetBodyParam(o.AcceptLogin); err != nil {
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
