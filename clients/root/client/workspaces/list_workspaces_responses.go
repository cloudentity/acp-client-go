// Code generated by go-swagger; DO NOT EDIT.

package workspaces

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// ListWorkspacesReader is a Reader for the ListWorkspaces structure.
type ListWorkspacesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListWorkspacesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListWorkspacesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListWorkspacesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListWorkspacesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListWorkspacesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListWorkspacesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/admin/tenants/{tenantID}/workspaces] listWorkspaces", response, response.Code())
	}
}

// NewListWorkspacesOK creates a ListWorkspacesOK with default headers values
func NewListWorkspacesOK() *ListWorkspacesOK {
	return &ListWorkspacesOK{}
}

/*
ListWorkspacesOK describes a response with status code 200, with default header values.

Workspaces
*/
type ListWorkspacesOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.WorkspacesResponse
}

// IsSuccess returns true when this list workspaces o k response has a 2xx status code
func (o *ListWorkspacesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list workspaces o k response has a 3xx status code
func (o *ListWorkspacesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list workspaces o k response has a 4xx status code
func (o *ListWorkspacesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list workspaces o k response has a 5xx status code
func (o *ListWorkspacesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list workspaces o k response a status code equal to that given
func (o *ListWorkspacesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list workspaces o k response
func (o *ListWorkspacesOK) Code() int {
	return 200
}

func (o *ListWorkspacesOK) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesOK  %+v", 200, o.Payload)
}

func (o *ListWorkspacesOK) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesOK  %+v", 200, o.Payload)
}

func (o *ListWorkspacesOK) GetPayload() *models.WorkspacesResponse {
	return o.Payload
}

func (o *ListWorkspacesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.WorkspacesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListWorkspacesUnauthorized creates a ListWorkspacesUnauthorized with default headers values
func NewListWorkspacesUnauthorized() *ListWorkspacesUnauthorized {
	return &ListWorkspacesUnauthorized{}
}

/*
ListWorkspacesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListWorkspacesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list workspaces unauthorized response has a 2xx status code
func (o *ListWorkspacesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list workspaces unauthorized response has a 3xx status code
func (o *ListWorkspacesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list workspaces unauthorized response has a 4xx status code
func (o *ListWorkspacesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list workspaces unauthorized response has a 5xx status code
func (o *ListWorkspacesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list workspaces unauthorized response a status code equal to that given
func (o *ListWorkspacesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list workspaces unauthorized response
func (o *ListWorkspacesUnauthorized) Code() int {
	return 401
}

func (o *ListWorkspacesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListWorkspacesUnauthorized) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListWorkspacesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListWorkspacesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListWorkspacesForbidden creates a ListWorkspacesForbidden with default headers values
func NewListWorkspacesForbidden() *ListWorkspacesForbidden {
	return &ListWorkspacesForbidden{}
}

/*
ListWorkspacesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListWorkspacesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list workspaces forbidden response has a 2xx status code
func (o *ListWorkspacesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list workspaces forbidden response has a 3xx status code
func (o *ListWorkspacesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list workspaces forbidden response has a 4xx status code
func (o *ListWorkspacesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list workspaces forbidden response has a 5xx status code
func (o *ListWorkspacesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list workspaces forbidden response a status code equal to that given
func (o *ListWorkspacesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list workspaces forbidden response
func (o *ListWorkspacesForbidden) Code() int {
	return 403
}

func (o *ListWorkspacesForbidden) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesForbidden  %+v", 403, o.Payload)
}

func (o *ListWorkspacesForbidden) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesForbidden  %+v", 403, o.Payload)
}

func (o *ListWorkspacesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListWorkspacesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListWorkspacesNotFound creates a ListWorkspacesNotFound with default headers values
func NewListWorkspacesNotFound() *ListWorkspacesNotFound {
	return &ListWorkspacesNotFound{}
}

/*
ListWorkspacesNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListWorkspacesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list workspaces not found response has a 2xx status code
func (o *ListWorkspacesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list workspaces not found response has a 3xx status code
func (o *ListWorkspacesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list workspaces not found response has a 4xx status code
func (o *ListWorkspacesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list workspaces not found response has a 5xx status code
func (o *ListWorkspacesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list workspaces not found response a status code equal to that given
func (o *ListWorkspacesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list workspaces not found response
func (o *ListWorkspacesNotFound) Code() int {
	return 404
}

func (o *ListWorkspacesNotFound) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesNotFound  %+v", 404, o.Payload)
}

func (o *ListWorkspacesNotFound) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesNotFound  %+v", 404, o.Payload)
}

func (o *ListWorkspacesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListWorkspacesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListWorkspacesTooManyRequests creates a ListWorkspacesTooManyRequests with default headers values
func NewListWorkspacesTooManyRequests() *ListWorkspacesTooManyRequests {
	return &ListWorkspacesTooManyRequests{}
}

/*
ListWorkspacesTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListWorkspacesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list workspaces too many requests response has a 2xx status code
func (o *ListWorkspacesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list workspaces too many requests response has a 3xx status code
func (o *ListWorkspacesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list workspaces too many requests response has a 4xx status code
func (o *ListWorkspacesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list workspaces too many requests response has a 5xx status code
func (o *ListWorkspacesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list workspaces too many requests response a status code equal to that given
func (o *ListWorkspacesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list workspaces too many requests response
func (o *ListWorkspacesTooManyRequests) Code() int {
	return 429
}

func (o *ListWorkspacesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListWorkspacesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /api/admin/tenants/{tenantID}/workspaces][%d] listWorkspacesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListWorkspacesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListWorkspacesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
