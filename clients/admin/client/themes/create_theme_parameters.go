// Code generated by go-swagger; DO NOT EDIT.

package themes

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

// NewCreateThemeParams creates a new CreateThemeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateThemeParams() *CreateThemeParams {
	return &CreateThemeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateThemeParamsWithTimeout creates a new CreateThemeParams object
// with the ability to set a timeout on a request.
func NewCreateThemeParamsWithTimeout(timeout time.Duration) *CreateThemeParams {
	return &CreateThemeParams{
		timeout: timeout,
	}
}

// NewCreateThemeParamsWithContext creates a new CreateThemeParams object
// with the ability to set a context for a request.
func NewCreateThemeParamsWithContext(ctx context.Context) *CreateThemeParams {
	return &CreateThemeParams{
		Context: ctx,
	}
}

// NewCreateThemeParamsWithHTTPClient creates a new CreateThemeParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateThemeParamsWithHTTPClient(client *http.Client) *CreateThemeParams {
	return &CreateThemeParams{
		HTTPClient: client,
	}
}

/*
CreateThemeParams contains all the parameters to send to the API endpoint

	for the create theme operation.

	Typically these are written to a http.Request.
*/
type CreateThemeParams struct {

	// Theme.
	Theme *models.Theme

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* SourceThemeID.

	   Optional source theme ID. The new theme will copy the source theme's templates.

	   Format: themeID
	*/
	SourceThemeID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateThemeParams) WithDefaults() *CreateThemeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateThemeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create theme params
func (o *CreateThemeParams) WithTimeout(timeout time.Duration) *CreateThemeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create theme params
func (o *CreateThemeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create theme params
func (o *CreateThemeParams) WithContext(ctx context.Context) *CreateThemeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create theme params
func (o *CreateThemeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create theme params
func (o *CreateThemeParams) WithHTTPClient(client *http.Client) *CreateThemeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create theme params
func (o *CreateThemeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTheme adds the theme to the create theme params
func (o *CreateThemeParams) WithTheme(theme *models.Theme) *CreateThemeParams {
	o.SetTheme(theme)
	return o
}

// SetTheme adds the theme to the create theme params
func (o *CreateThemeParams) SetTheme(theme *models.Theme) {
	o.Theme = theme
}

// WithIfMatch adds the ifMatch to the create theme params
func (o *CreateThemeParams) WithIfMatch(ifMatch *string) *CreateThemeParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create theme params
func (o *CreateThemeParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithSourceThemeID adds the sourceThemeID to the create theme params
func (o *CreateThemeParams) WithSourceThemeID(sourceThemeID *string) *CreateThemeParams {
	o.SetSourceThemeID(sourceThemeID)
	return o
}

// SetSourceThemeID adds the sourceThemeId to the create theme params
func (o *CreateThemeParams) SetSourceThemeID(sourceThemeID *string) {
	o.SourceThemeID = sourceThemeID
}

// WriteToRequest writes these params to a swagger request
func (o *CreateThemeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Theme != nil {
		if err := r.SetBodyParam(o.Theme); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if o.SourceThemeID != nil {

		// query param source_theme_id
		var qrSourceThemeID string

		if o.SourceThemeID != nil {
			qrSourceThemeID = *o.SourceThemeID
		}
		qSourceThemeID := qrSourceThemeID
		if qSourceThemeID != "" {

			if err := r.SetQueryParam("source_theme_id", qSourceThemeID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
