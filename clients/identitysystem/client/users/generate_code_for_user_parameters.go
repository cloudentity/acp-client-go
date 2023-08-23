// Code generated by go-swagger; DO NOT EDIT.

package users

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

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// NewGenerateCodeForUserParams creates a new GenerateCodeForUserParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGenerateCodeForUserParams() *GenerateCodeForUserParams {
	return &GenerateCodeForUserParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGenerateCodeForUserParamsWithTimeout creates a new GenerateCodeForUserParams object
// with the ability to set a timeout on a request.
func NewGenerateCodeForUserParamsWithTimeout(timeout time.Duration) *GenerateCodeForUserParams {
	return &GenerateCodeForUserParams{
		timeout: timeout,
	}
}

// NewGenerateCodeForUserParamsWithContext creates a new GenerateCodeForUserParams object
// with the ability to set a context for a request.
func NewGenerateCodeForUserParamsWithContext(ctx context.Context) *GenerateCodeForUserParams {
	return &GenerateCodeForUserParams{
		Context: ctx,
	}
}

// NewGenerateCodeForUserParamsWithHTTPClient creates a new GenerateCodeForUserParams object
// with the ability to set a custom HTTPClient for a request.
func NewGenerateCodeForUserParamsWithHTTPClient(client *http.Client) *GenerateCodeForUserParams {
	return &GenerateCodeForUserParams{
		HTTPClient: client,
	}
}

/*
GenerateCodeForUserParams contains all the parameters to send to the API endpoint

	for the generate code for user operation.

	Typically these are written to a http.Request.
*/
type GenerateCodeForUserParams struct {

	// CodeRequest.
	CodeRequest *models.RequestCodeForUser

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the generate code for user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GenerateCodeForUserParams) WithDefaults() *GenerateCodeForUserParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the generate code for user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GenerateCodeForUserParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the generate code for user params
func (o *GenerateCodeForUserParams) WithTimeout(timeout time.Duration) *GenerateCodeForUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the generate code for user params
func (o *GenerateCodeForUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the generate code for user params
func (o *GenerateCodeForUserParams) WithContext(ctx context.Context) *GenerateCodeForUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the generate code for user params
func (o *GenerateCodeForUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the generate code for user params
func (o *GenerateCodeForUserParams) WithHTTPClient(client *http.Client) *GenerateCodeForUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the generate code for user params
func (o *GenerateCodeForUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCodeRequest adds the codeRequest to the generate code for user params
func (o *GenerateCodeForUserParams) WithCodeRequest(codeRequest *models.RequestCodeForUser) *GenerateCodeForUserParams {
	o.SetCodeRequest(codeRequest)
	return o
}

// SetCodeRequest adds the codeRequest to the generate code for user params
func (o *GenerateCodeForUserParams) SetCodeRequest(codeRequest *models.RequestCodeForUser) {
	o.CodeRequest = codeRequest
}

// WithIfMatch adds the ifMatch to the generate code for user params
func (o *GenerateCodeForUserParams) WithIfMatch(ifMatch *string) *GenerateCodeForUserParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the generate code for user params
func (o *GenerateCodeForUserParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the generate code for user params
func (o *GenerateCodeForUserParams) WithIPID(iPID string) *GenerateCodeForUserParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the generate code for user params
func (o *GenerateCodeForUserParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *GenerateCodeForUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CodeRequest != nil {
		if err := r.SetBodyParam(o.CodeRequest); err != nil {
			return err
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}