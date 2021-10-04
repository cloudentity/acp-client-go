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

	"github.com/cloudentity/acp-client-go/models"
)

// NewSetCIBAAuthenticationServiceParams creates a new SetCIBAAuthenticationServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSetCIBAAuthenticationServiceParams() *SetCIBAAuthenticationServiceParams {
	return &SetCIBAAuthenticationServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSetCIBAAuthenticationServiceParamsWithTimeout creates a new SetCIBAAuthenticationServiceParams object
// with the ability to set a timeout on a request.
func NewSetCIBAAuthenticationServiceParamsWithTimeout(timeout time.Duration) *SetCIBAAuthenticationServiceParams {
	return &SetCIBAAuthenticationServiceParams{
		timeout: timeout,
	}
}

// NewSetCIBAAuthenticationServiceParamsWithContext creates a new SetCIBAAuthenticationServiceParams object
// with the ability to set a context for a request.
func NewSetCIBAAuthenticationServiceParamsWithContext(ctx context.Context) *SetCIBAAuthenticationServiceParams {
	return &SetCIBAAuthenticationServiceParams{
		Context: ctx,
	}
}

// NewSetCIBAAuthenticationServiceParamsWithHTTPClient creates a new SetCIBAAuthenticationServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewSetCIBAAuthenticationServiceParamsWithHTTPClient(client *http.Client) *SetCIBAAuthenticationServiceParams {
	return &SetCIBAAuthenticationServiceParams{
		HTTPClient: client,
	}
}

/* SetCIBAAuthenticationServiceParams contains all the parameters to send to the API endpoint
   for the set c i b a authentication service operation.

   Typically these are written to a http.Request.
*/
type SetCIBAAuthenticationServiceParams struct {

	/* CIBAAuthenticationService.

	   CIBA authentication service
	*/
	CIBAAuthenticationService *models.CIBAAuthenticationService

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the set c i b a authentication service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetCIBAAuthenticationServiceParams) WithDefaults() *SetCIBAAuthenticationServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the set c i b a authentication service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetCIBAAuthenticationServiceParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := SetCIBAAuthenticationServiceParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithTimeout(timeout time.Duration) *SetCIBAAuthenticationServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithContext(ctx context.Context) *SetCIBAAuthenticationServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithHTTPClient(client *http.Client) *SetCIBAAuthenticationServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCIBAAuthenticationService adds the cIBAAuthenticationService to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithCIBAAuthenticationService(cIBAAuthenticationService *models.CIBAAuthenticationService) *SetCIBAAuthenticationServiceParams {
	o.SetCIBAAuthenticationService(cIBAAuthenticationService)
	return o
}

// SetCIBAAuthenticationService adds the cIBAAuthenticationService to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetCIBAAuthenticationService(cIBAAuthenticationService *models.CIBAAuthenticationService) {
	o.CIBAAuthenticationService = cIBAAuthenticationService
}

// WithAid adds the aid to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithAid(aid string) *SetCIBAAuthenticationServiceParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) WithTid(tid string) *SetCIBAAuthenticationServiceParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the set c i b a authentication service params
func (o *SetCIBAAuthenticationServiceParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *SetCIBAAuthenticationServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CIBAAuthenticationService != nil {
		if err := r.SetBodyParam(o.CIBAAuthenticationService); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
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
