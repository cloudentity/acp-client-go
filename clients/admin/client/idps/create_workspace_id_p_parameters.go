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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewCreateWorkspaceIDPParams creates a new CreateWorkspaceIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateWorkspaceIDPParams() *CreateWorkspaceIDPParams {
	return &CreateWorkspaceIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateWorkspaceIDPParamsWithTimeout creates a new CreateWorkspaceIDPParams object
// with the ability to set a timeout on a request.
func NewCreateWorkspaceIDPParamsWithTimeout(timeout time.Duration) *CreateWorkspaceIDPParams {
	return &CreateWorkspaceIDPParams{
		timeout: timeout,
	}
}

// NewCreateWorkspaceIDPParamsWithContext creates a new CreateWorkspaceIDPParams object
// with the ability to set a context for a request.
func NewCreateWorkspaceIDPParamsWithContext(ctx context.Context) *CreateWorkspaceIDPParams {
	return &CreateWorkspaceIDPParams{
		Context: ctx,
	}
}

// NewCreateWorkspaceIDPParamsWithHTTPClient creates a new CreateWorkspaceIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateWorkspaceIDPParamsWithHTTPClient(client *http.Client) *CreateWorkspaceIDPParams {
	return &CreateWorkspaceIDPParams{
		HTTPClient: client,
	}
}

/*
CreateWorkspaceIDPParams contains all the parameters to send to the API endpoint

	for the create workspace ID p operation.

	Typically these are written to a http.Request.
*/
type CreateWorkspaceIDPParams struct {

	/* WorkspaceIDP.

	   WorkspaceIDP
	*/
	WorkspaceIDP *models.WorkspaceIDP

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create workspace ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateWorkspaceIDPParams) WithDefaults() *CreateWorkspaceIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create workspace ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateWorkspaceIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateWorkspaceIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithTimeout(timeout time.Duration) *CreateWorkspaceIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithContext(ctx context.Context) *CreateWorkspaceIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithHTTPClient(client *http.Client) *CreateWorkspaceIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWorkspaceIDP adds the workspaceIDP to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithWorkspaceIDP(workspaceIDP *models.WorkspaceIDP) *CreateWorkspaceIDPParams {
	o.SetWorkspaceIDP(workspaceIDP)
	return o
}

// SetWorkspaceIDP adds the workspaceIdP to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetWorkspaceIDP(workspaceIDP *models.WorkspaceIDP) {
	o.WorkspaceIDP = workspaceIDP
}

// WithIfMatch adds the ifMatch to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithIfMatch(ifMatch *string) *CreateWorkspaceIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) WithWid(wid string) *CreateWorkspaceIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create workspace ID p params
func (o *CreateWorkspaceIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateWorkspaceIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.WorkspaceIDP != nil {
		if err := r.SetBodyParam(o.WorkspaceIDP); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
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
