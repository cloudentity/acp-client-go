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

// ListUserRolesReader is a Reader for the ListUserRoles structure.
type ListUserRolesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListUserRolesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListUserRolesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListUserRolesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewListUserRolesForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListUserRolesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewListUserRolesTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /pools/{ipID}/users/{userID}/roles] listUserRoles", response, response.Code())
	}
}

// NewListUserRolesOK creates a ListUserRolesOK with default headers values
func NewListUserRolesOK() *ListUserRolesOK {
	return &ListUserRolesOK{}
}

/*
ListUserRolesOK describes a response with status code 200, with default header values.

UserRoles
*/
type ListUserRolesOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.RoleResources
}

// IsSuccess returns true when this list user roles o k response has a 2xx status code
func (o *ListUserRolesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list user roles o k response has a 3xx status code
func (o *ListUserRolesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user roles o k response has a 4xx status code
func (o *ListUserRolesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list user roles o k response has a 5xx status code
func (o *ListUserRolesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list user roles o k response a status code equal to that given
func (o *ListUserRolesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list user roles o k response
func (o *ListUserRolesOK) Code() int {
	return 200
}

func (o *ListUserRolesOK) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesOK  %+v", 200, o.Payload)
}

func (o *ListUserRolesOK) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesOK  %+v", 200, o.Payload)
}

func (o *ListUserRolesOK) GetPayload() *models.RoleResources {
	return o.Payload
}

func (o *ListUserRolesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.RoleResources)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserRolesUnauthorized creates a ListUserRolesUnauthorized with default headers values
func NewListUserRolesUnauthorized() *ListUserRolesUnauthorized {
	return &ListUserRolesUnauthorized{}
}

/*
ListUserRolesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type ListUserRolesUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user roles unauthorized response has a 2xx status code
func (o *ListUserRolesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user roles unauthorized response has a 3xx status code
func (o *ListUserRolesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user roles unauthorized response has a 4xx status code
func (o *ListUserRolesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user roles unauthorized response has a 5xx status code
func (o *ListUserRolesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this list user roles unauthorized response a status code equal to that given
func (o *ListUserRolesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the list user roles unauthorized response
func (o *ListUserRolesUnauthorized) Code() int {
	return 401
}

func (o *ListUserRolesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListUserRolesUnauthorized) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesUnauthorized  %+v", 401, o.Payload)
}

func (o *ListUserRolesUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserRolesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserRolesForbidden creates a ListUserRolesForbidden with default headers values
func NewListUserRolesForbidden() *ListUserRolesForbidden {
	return &ListUserRolesForbidden{}
}

/*
ListUserRolesForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ListUserRolesForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user roles forbidden response has a 2xx status code
func (o *ListUserRolesForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user roles forbidden response has a 3xx status code
func (o *ListUserRolesForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user roles forbidden response has a 4xx status code
func (o *ListUserRolesForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user roles forbidden response has a 5xx status code
func (o *ListUserRolesForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this list user roles forbidden response a status code equal to that given
func (o *ListUserRolesForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the list user roles forbidden response
func (o *ListUserRolesForbidden) Code() int {
	return 403
}

func (o *ListUserRolesForbidden) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesForbidden  %+v", 403, o.Payload)
}

func (o *ListUserRolesForbidden) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesForbidden  %+v", 403, o.Payload)
}

func (o *ListUserRolesForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserRolesForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserRolesNotFound creates a ListUserRolesNotFound with default headers values
func NewListUserRolesNotFound() *ListUserRolesNotFound {
	return &ListUserRolesNotFound{}
}

/*
ListUserRolesNotFound describes a response with status code 404, with default header values.

Not found
*/
type ListUserRolesNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user roles not found response has a 2xx status code
func (o *ListUserRolesNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user roles not found response has a 3xx status code
func (o *ListUserRolesNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user roles not found response has a 4xx status code
func (o *ListUserRolesNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user roles not found response has a 5xx status code
func (o *ListUserRolesNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this list user roles not found response a status code equal to that given
func (o *ListUserRolesNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the list user roles not found response
func (o *ListUserRolesNotFound) Code() int {
	return 404
}

func (o *ListUserRolesNotFound) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesNotFound  %+v", 404, o.Payload)
}

func (o *ListUserRolesNotFound) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesNotFound  %+v", 404, o.Payload)
}

func (o *ListUserRolesNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserRolesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListUserRolesTooManyRequests creates a ListUserRolesTooManyRequests with default headers values
func NewListUserRolesTooManyRequests() *ListUserRolesTooManyRequests {
	return &ListUserRolesTooManyRequests{}
}

/*
ListUserRolesTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type ListUserRolesTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this list user roles too many requests response has a 2xx status code
func (o *ListUserRolesTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this list user roles too many requests response has a 3xx status code
func (o *ListUserRolesTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user roles too many requests response has a 4xx status code
func (o *ListUserRolesTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this list user roles too many requests response has a 5xx status code
func (o *ListUserRolesTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this list user roles too many requests response a status code equal to that given
func (o *ListUserRolesTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the list user roles too many requests response
func (o *ListUserRolesTooManyRequests) Code() int {
	return 429
}

func (o *ListUserRolesTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListUserRolesTooManyRequests) String() string {
	return fmt.Sprintf("[GET /pools/{ipID}/users/{userID}/roles][%d] listUserRolesTooManyRequests  %+v", 429, o.Payload)
}

func (o *ListUserRolesTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *ListUserRolesTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
