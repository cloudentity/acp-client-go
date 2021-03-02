// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// NewCreateGithubIDPParams creates a new CreateGithubIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateGithubIDPParams() *CreateGithubIDPParams {
	return &CreateGithubIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateGithubIDPParamsWithTimeout creates a new CreateGithubIDPParams object
// with the ability to set a timeout on a request.
func NewCreateGithubIDPParamsWithTimeout(timeout time.Duration) *CreateGithubIDPParams {
	return &CreateGithubIDPParams{
		timeout: timeout,
	}
}

// NewCreateGithubIDPParamsWithContext creates a new CreateGithubIDPParams object
// with the ability to set a context for a request.
func NewCreateGithubIDPParamsWithContext(ctx context.Context) *CreateGithubIDPParams {
	return &CreateGithubIDPParams{
		Context: ctx,
	}
}

// NewCreateGithubIDPParamsWithHTTPClient creates a new CreateGithubIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateGithubIDPParamsWithHTTPClient(client *http.Client) *CreateGithubIDPParams {
	return &CreateGithubIDPParams{
		HTTPClient: client,
	}
}

/* CreateGithubIDPParams contains all the parameters to send to the API endpoint
   for the create github ID p operation.

   Typically these are written to a http.Request.
*/
type CreateGithubIDPParams struct {

	/* GithubIDP.

	   GithubIDP
	*/
	GithubIDP *models.GithubIDP

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

// WithDefaults hydrates default values in the create github ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateGithubIDPParams) WithDefaults() *CreateGithubIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create github ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateGithubIDPParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := CreateGithubIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create github ID p params
func (o *CreateGithubIDPParams) WithTimeout(timeout time.Duration) *CreateGithubIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create github ID p params
func (o *CreateGithubIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create github ID p params
func (o *CreateGithubIDPParams) WithContext(ctx context.Context) *CreateGithubIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create github ID p params
func (o *CreateGithubIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create github ID p params
func (o *CreateGithubIDPParams) WithHTTPClient(client *http.Client) *CreateGithubIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create github ID p params
func (o *CreateGithubIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGithubIDP adds the githubIDP to the create github ID p params
func (o *CreateGithubIDPParams) WithGithubIDP(githubIDP *models.GithubIDP) *CreateGithubIDPParams {
	o.SetGithubIDP(githubIDP)
	return o
}

// SetGithubIDP adds the githubIdP to the create github ID p params
func (o *CreateGithubIDPParams) SetGithubIDP(githubIDP *models.GithubIDP) {
	o.GithubIDP = githubIDP
}

// WithAid adds the aid to the create github ID p params
func (o *CreateGithubIDPParams) WithAid(aid string) *CreateGithubIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the create github ID p params
func (o *CreateGithubIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the create github ID p params
func (o *CreateGithubIDPParams) WithTid(tid string) *CreateGithubIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the create github ID p params
func (o *CreateGithubIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateGithubIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.GithubIDP != nil {
		if err := r.SetBodyParam(o.GithubIDP); err != nil {
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
