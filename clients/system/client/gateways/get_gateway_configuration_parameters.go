// Code generated by go-swagger; DO NOT EDIT.

package gateways

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

// NewGetGatewayConfigurationParams creates a new GetGatewayConfigurationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetGatewayConfigurationParams() *GetGatewayConfigurationParams {
	return &GetGatewayConfigurationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetGatewayConfigurationParamsWithTimeout creates a new GetGatewayConfigurationParams object
// with the ability to set a timeout on a request.
func NewGetGatewayConfigurationParamsWithTimeout(timeout time.Duration) *GetGatewayConfigurationParams {
	return &GetGatewayConfigurationParams{
		timeout: timeout,
	}
}

// NewGetGatewayConfigurationParamsWithContext creates a new GetGatewayConfigurationParams object
// with the ability to set a context for a request.
func NewGetGatewayConfigurationParamsWithContext(ctx context.Context) *GetGatewayConfigurationParams {
	return &GetGatewayConfigurationParams{
		Context: ctx,
	}
}

// NewGetGatewayConfigurationParamsWithHTTPClient creates a new GetGatewayConfigurationParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetGatewayConfigurationParamsWithHTTPClient(client *http.Client) *GetGatewayConfigurationParams {
	return &GetGatewayConfigurationParams{
		HTTPClient: client,
	}
}

/*
GetGatewayConfigurationParams contains all the parameters to send to the API endpoint

	for the get gateway configuration operation.

	Typically these are written to a http.Request.
*/
type GetGatewayConfigurationParams struct {

	/* AuthorizerVersion.

	   Authorizer version

	   Default: "latest"
	*/
	AuthorizerVersion *string

	/* ServerID.

	   Server id
	*/
	ServerID *string

	/* TenantID.

	   Tenant id
	*/
	TenantID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get gateway configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGatewayConfigurationParams) WithDefaults() *GetGatewayConfigurationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get gateway configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGatewayConfigurationParams) SetDefaults() {
	var (
		authorizerVersionDefault = string("latest")
	)

	val := GetGatewayConfigurationParams{
		AuthorizerVersion: &authorizerVersionDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithTimeout(timeout time.Duration) *GetGatewayConfigurationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithContext(ctx context.Context) *GetGatewayConfigurationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithHTTPClient(client *http.Client) *GetGatewayConfigurationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorizerVersion adds the authorizerVersion to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithAuthorizerVersion(authorizerVersion *string) *GetGatewayConfigurationParams {
	o.SetAuthorizerVersion(authorizerVersion)
	return o
}

// SetAuthorizerVersion adds the authorizerVersion to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetAuthorizerVersion(authorizerVersion *string) {
	o.AuthorizerVersion = authorizerVersion
}

// WithServerID adds the serverID to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithServerID(serverID *string) *GetGatewayConfigurationParams {
	o.SetServerID(serverID)
	return o
}

// SetServerID adds the serverId to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetServerID(serverID *string) {
	o.ServerID = serverID
}

// WithTenantID adds the tenantID to the get gateway configuration params
func (o *GetGatewayConfigurationParams) WithTenantID(tenantID *string) *GetGatewayConfigurationParams {
	o.SetTenantID(tenantID)
	return o
}

// SetTenantID adds the tenantId to the get gateway configuration params
func (o *GetGatewayConfigurationParams) SetTenantID(tenantID *string) {
	o.TenantID = tenantID
}

// WriteToRequest writes these params to a swagger request
func (o *GetGatewayConfigurationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AuthorizerVersion != nil {

		// query param authorizer_version
		var qrAuthorizerVersion string

		if o.AuthorizerVersion != nil {
			qrAuthorizerVersion = *o.AuthorizerVersion
		}
		qAuthorizerVersion := qrAuthorizerVersion
		if qAuthorizerVersion != "" {

			if err := r.SetQueryParam("authorizer_version", qAuthorizerVersion); err != nil {
				return err
			}
		}
	}

	if o.ServerID != nil {

		// query param server_id
		var qrServerID string

		if o.ServerID != nil {
			qrServerID = *o.ServerID
		}
		qServerID := qrServerID
		if qServerID != "" {

			if err := r.SetQueryParam("server_id", qServerID); err != nil {
				return err
			}
		}
	}

	if o.TenantID != nil {

		// query param tenant_id
		var qrTenantID string

		if o.TenantID != nil {
			qrTenantID = *o.TenantID
		}
		qTenantID := qrTenantID
		if qTenantID != "" {

			if err := r.SetQueryParam("tenant_id", qTenantID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
