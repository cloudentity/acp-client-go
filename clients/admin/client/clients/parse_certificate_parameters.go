// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewParseCertificateParams creates a new ParseCertificateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewParseCertificateParams() *ParseCertificateParams {
	return &ParseCertificateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewParseCertificateParamsWithTimeout creates a new ParseCertificateParams object
// with the ability to set a timeout on a request.
func NewParseCertificateParamsWithTimeout(timeout time.Duration) *ParseCertificateParams {
	return &ParseCertificateParams{
		timeout: timeout,
	}
}

// NewParseCertificateParamsWithContext creates a new ParseCertificateParams object
// with the ability to set a context for a request.
func NewParseCertificateParamsWithContext(ctx context.Context) *ParseCertificateParams {
	return &ParseCertificateParams{
		Context: ctx,
	}
}

// NewParseCertificateParamsWithHTTPClient creates a new ParseCertificateParams object
// with the ability to set a custom HTTPClient for a request.
func NewParseCertificateParamsWithHTTPClient(client *http.Client) *ParseCertificateParams {
	return &ParseCertificateParams{
		HTTPClient: client,
	}
}

/*
ParseCertificateParams contains all the parameters to send to the API endpoint

	for the parse certificate operation.

	Typically these are written to a http.Request.
*/
type ParseCertificateParams struct {

	// File.
	File runtime.NamedReadCloser

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the parse certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ParseCertificateParams) WithDefaults() *ParseCertificateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the parse certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ParseCertificateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the parse certificate params
func (o *ParseCertificateParams) WithTimeout(timeout time.Duration) *ParseCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the parse certificate params
func (o *ParseCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the parse certificate params
func (o *ParseCertificateParams) WithContext(ctx context.Context) *ParseCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the parse certificate params
func (o *ParseCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the parse certificate params
func (o *ParseCertificateParams) WithHTTPClient(client *http.Client) *ParseCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the parse certificate params
func (o *ParseCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFile adds the file to the parse certificate params
func (o *ParseCertificateParams) WithFile(file runtime.NamedReadCloser) *ParseCertificateParams {
	o.SetFile(file)
	return o
}

// SetFile adds the file to the parse certificate params
func (o *ParseCertificateParams) SetFile(file runtime.NamedReadCloser) {
	o.File = file
}

// WriteToRequest writes these params to a swagger request
func (o *ParseCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.File != nil {

		if o.File != nil {
			// form file param file
			if err := r.SetFileParam("file", o.File); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}