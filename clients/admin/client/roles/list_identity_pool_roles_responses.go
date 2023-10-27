// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// ListIdentityPoolRolesReader is a Reader for the ListIdentityPoolRoles structure.
type ListIdentityPoolRolesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListIdentityPoolRolesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListIdentityPoolRolesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListIdentityPoolRolesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListIdentityPoolRolesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListIdentityPoolRolesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListIdentityPoolRolesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /pools/{ipID}/roles] listIdentityPoolRoles", response, response.Code())
	}
}

// NewListIdentityPoolRolesOK creates a ListIdentityPoolRolesOK with default headers values
func NewListIdentityPoolRolesOK() *ListIdentityPoolRolesOK {
	return &ListIdentityPoolRolesOK{}
}

/*
ListIdentityPoolRolesOK describes a response with status code 200, with default header values.

IdentityPoolRoles
*/
type ListIdentityPoolRolesOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.IdentityPoolRolesResponse
}

// IsSuccess returns true when this list identity pool roles o k response has a 2xx status code
func (o *ListIdentityPoolRolesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list identity pool roles o k response has a 3xx status code
func (o *ListIdentityPoolRolesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list identity pool roles o k response has a 4xx status code
func (o *ListIdentityPoolRolesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list identity pool roles o k response has a 5xx status code
func (o *ListIdentityPoolRolesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list identity pool roles o k response a status code equal to that given
func (o *ListIdentityPoolRolesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list identity pool roles o k response
func (o *ListIdentityPoolRolesOK) Code() int {
	return 200
}

func (o *ListIdentityPoolRolesOK) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesOK  %+v", 200, o.Payload)
}

func (o *ListIdentityPoolRolesOK) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesOK  %+v", 200, o.Payload)
}

func (o *ListIdentityPoolRolesOK) GetPayload() *models.IdentityPoolRolesResponse {
	return o.Payload
}

func (o *ListIdentityPoolRolesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.IdentityPoolRolesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIdentityPoolRolesUnauthorized creates a ListIdentityPoolRolesUnauthorized with default headers values
func NewListIdentityPoolRolesUnauthorized() *ListIdentityPoolRolesUnauthorized {
	return &ListIdentityPoolRolesUnauthorized{}
}

/*
ListIdentityPoolRolesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListIdentityPoolRolesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list identity pool roles unauthorized response has a 2xx status code
func (o *ListIdentityPoolRolesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list identity pool roles unauthorized response has a 3xx status code
func (o *ListIdentityPoolRolesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list identity pool roles unauthorized response has a 4xx status code
func (o *ListIdentityPoolRolesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list identity pool roles unauthorized response has a 5xx status code
func (o *ListIdentityPoolRolesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list identity pool roles unauthorized response a status code equal to that given
func (o *ListIdentityPoolRolesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list identity pool roles unauthorized response
func (o *ListIdentityPoolRolesUnauthorized) Code() int {
	return 401
}

func (o *ListIdentityPoolRolesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIdentityPoolRolesUnauthorized) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListIdentityPoolRolesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIdentityPoolRolesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIdentityPoolRolesForbidden creates a ListIdentityPoolRolesForbidden with default headers values
func NewListIdentityPoolRolesForbidden() *ListIdentityPoolRolesForbidden {
	return &ListIdentityPoolRolesForbidden{}
}

/*
ListIdentityPoolRolesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListIdentityPoolRolesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list identity pool roles forbidden response has a 2xx status code
func (o *ListIdentityPoolRolesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list identity pool roles forbidden response has a 3xx status code
func (o *ListIdentityPoolRolesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list identity pool roles forbidden response has a 4xx status code
func (o *ListIdentityPoolRolesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list identity pool roles forbidden response has a 5xx status code
func (o *ListIdentityPoolRolesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list identity pool roles forbidden response a status code equal to that given
func (o *ListIdentityPoolRolesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list identity pool roles forbidden response
func (o *ListIdentityPoolRolesForbidden) Code() int {
	return 403
}

func (o *ListIdentityPoolRolesForbidden) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesForbidden  %+v", 403, o.Payload)
}

func (o *ListIdentityPoolRolesForbidden) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesForbidden  %+v", 403, o.Payload)
}

func (o *ListIdentityPoolRolesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIdentityPoolRolesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIdentityPoolRolesNotFound creates a ListIdentityPoolRolesNotFound with default headers values
func NewListIdentityPoolRolesNotFound() *ListIdentityPoolRolesNotFound {
	return &ListIdentityPoolRolesNotFound{}
}

/*
ListIdentityPoolRolesNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListIdentityPoolRolesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list identity pool roles not found response has a 2xx status code
func (o *ListIdentityPoolRolesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list identity pool roles not found response has a 3xx status code
func (o *ListIdentityPoolRolesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list identity pool roles not found response has a 4xx status code
func (o *ListIdentityPoolRolesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list identity pool roles not found response has a 5xx status code
func (o *ListIdentityPoolRolesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list identity pool roles not found response a status code equal to that given
func (o *ListIdentityPoolRolesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list identity pool roles not found response
func (o *ListIdentityPoolRolesNotFound) Code() int {
	return 404
}

func (o *ListIdentityPoolRolesNotFound) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesNotFound  %+v", 404, o.Payload)
}

func (o *ListIdentityPoolRolesNotFound) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesNotFound  %+v", 404, o.Payload)
}

func (o *ListIdentityPoolRolesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIdentityPoolRolesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListIdentityPoolRolesTooManyRequests creates a ListIdentityPoolRolesTooManyRequests with default headers values
func NewListIdentityPoolRolesTooManyRequests() *ListIdentityPoolRolesTooManyRequests {
	return &ListIdentityPoolRolesTooManyRequests{}
}

/*
ListIdentityPoolRolesTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListIdentityPoolRolesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list identity pool roles too many requests response has a 2xx status code
func (o *ListIdentityPoolRolesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list identity pool roles too many requests response has a 3xx status code
func (o *ListIdentityPoolRolesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list identity pool roles too many requests response has a 4xx status code
func (o *ListIdentityPoolRolesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list identity pool roles too many requests response has a 5xx status code
func (o *ListIdentityPoolRolesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list identity pool roles too many requests response a status code equal to that given
func (o *ListIdentityPoolRolesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list identity pool roles too many requests response
func (o *ListIdentityPoolRolesTooManyRequests) Code() int {
	return 429
}

func (o *ListIdentityPoolRolesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIdentityPoolRolesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/roles][%d] listIdentityPoolRolesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListIdentityPoolRolesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListIdentityPoolRolesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}