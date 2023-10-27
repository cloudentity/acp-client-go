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

// GrantIdentityPoolRoleReader is a Reader for the GrantIdentityPoolRole structure.
type GrantIdentityPoolRoleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GrantIdentityPoolRoleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewGrantIdentityPoolRoleNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGrantIdentityPoolRoleUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGrantIdentityPoolRoleForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGrantIdentityPoolRoleNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewGrantIdentityPoolRoleUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGrantIdentityPoolRoleTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /pools/{ipID}/roles/grant] grantIdentityPoolRole", response, response.Code())
	}
}

// NewGrantIdentityPoolRoleNoContent creates a GrantIdentityPoolRoleNoContent with default headers values
func NewGrantIdentityPoolRoleNoContent() *GrantIdentityPoolRoleNoContent {
	return &GrantIdentityPoolRoleNoContent{}
}

/*
GrantIdentityPoolRoleNoContent describes a response with status code 204, with default header values.

Role granted
*/
type GrantIdentityPoolRoleNoContent struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string
}

// IsSuccess returns true when this grant identity pool role no content response has a 2xx status code
func (o *GrantIdentityPoolRoleNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this grant identity pool role no content response has a 3xx status code
func (o *GrantIdentityPoolRoleNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role no content response has a 4xx status code
func (o *GrantIdentityPoolRoleNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this grant identity pool role no content response has a 5xx status code
func (o *GrantIdentityPoolRoleNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role no content response a status code equal to that given
func (o *GrantIdentityPoolRoleNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the grant identity pool role no content response
func (o *GrantIdentityPoolRoleNoContent) Code() int {
	return 204
}

func (o *GrantIdentityPoolRoleNoContent) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleNoContent ", 204)
}

func (o *GrantIdentityPoolRoleNoContent) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleNoContent ", 204)
}

func (o *GrantIdentityPoolRoleNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	return nil
}

// NewGrantIdentityPoolRoleUnauthorized creates a GrantIdentityPoolRoleUnauthorized with default headers values
func NewGrantIdentityPoolRoleUnauthorized() *GrantIdentityPoolRoleUnauthorized {
	return &GrantIdentityPoolRoleUnauthorized{}
}

/*
GrantIdentityPoolRoleUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GrantIdentityPoolRoleUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant identity pool role unauthorized response has a 2xx status code
func (o *GrantIdentityPoolRoleUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant identity pool role unauthorized response has a 3xx status code
func (o *GrantIdentityPoolRoleUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role unauthorized response has a 4xx status code
func (o *GrantIdentityPoolRoleUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant identity pool role unauthorized response has a 5xx status code
func (o *GrantIdentityPoolRoleUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role unauthorized response a status code equal to that given
func (o *GrantIdentityPoolRoleUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the grant identity pool role unauthorized response
func (o *GrantIdentityPoolRoleUnauthorized) Code() int {
	return 401
}

func (o *GrantIdentityPoolRoleUnauthorized) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleUnauthorized  %+v", 401, o.Payload)
}

func (o *GrantIdentityPoolRoleUnauthorized) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleUnauthorized  %+v", 401, o.Payload)
}

func (o *GrantIdentityPoolRoleUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantIdentityPoolRoleUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantIdentityPoolRoleForbidden creates a GrantIdentityPoolRoleForbidden with default headers values
func NewGrantIdentityPoolRoleForbidden() *GrantIdentityPoolRoleForbidden {
	return &GrantIdentityPoolRoleForbidden{}
}

/*
GrantIdentityPoolRoleForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GrantIdentityPoolRoleForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant identity pool role forbidden response has a 2xx status code
func (o *GrantIdentityPoolRoleForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant identity pool role forbidden response has a 3xx status code
func (o *GrantIdentityPoolRoleForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role forbidden response has a 4xx status code
func (o *GrantIdentityPoolRoleForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant identity pool role forbidden response has a 5xx status code
func (o *GrantIdentityPoolRoleForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role forbidden response a status code equal to that given
func (o *GrantIdentityPoolRoleForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the grant identity pool role forbidden response
func (o *GrantIdentityPoolRoleForbidden) Code() int {
	return 403
}

func (o *GrantIdentityPoolRoleForbidden) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleForbidden  %+v", 403, o.Payload)
}

func (o *GrantIdentityPoolRoleForbidden) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleForbidden  %+v", 403, o.Payload)
}

func (o *GrantIdentityPoolRoleForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantIdentityPoolRoleForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantIdentityPoolRoleNotFound creates a GrantIdentityPoolRoleNotFound with default headers values
func NewGrantIdentityPoolRoleNotFound() *GrantIdentityPoolRoleNotFound {
	return &GrantIdentityPoolRoleNotFound{}
}

/*
GrantIdentityPoolRoleNotFound describes a response with status code 404, with default header values.

Not found
*/
type GrantIdentityPoolRoleNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant identity pool role not found response has a 2xx status code
func (o *GrantIdentityPoolRoleNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant identity pool role not found response has a 3xx status code
func (o *GrantIdentityPoolRoleNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role not found response has a 4xx status code
func (o *GrantIdentityPoolRoleNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant identity pool role not found response has a 5xx status code
func (o *GrantIdentityPoolRoleNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role not found response a status code equal to that given
func (o *GrantIdentityPoolRoleNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the grant identity pool role not found response
func (o *GrantIdentityPoolRoleNotFound) Code() int {
	return 404
}

func (o *GrantIdentityPoolRoleNotFound) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleNotFound  %+v", 404, o.Payload)
}

func (o *GrantIdentityPoolRoleNotFound) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleNotFound  %+v", 404, o.Payload)
}

func (o *GrantIdentityPoolRoleNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantIdentityPoolRoleNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantIdentityPoolRoleUnprocessableEntity creates a GrantIdentityPoolRoleUnprocessableEntity with default headers values
func NewGrantIdentityPoolRoleUnprocessableEntity() *GrantIdentityPoolRoleUnprocessableEntity {
	return &GrantIdentityPoolRoleUnprocessableEntity{}
}

/*
GrantIdentityPoolRoleUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type GrantIdentityPoolRoleUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant identity pool role unprocessable entity response has a 2xx status code
func (o *GrantIdentityPoolRoleUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant identity pool role unprocessable entity response has a 3xx status code
func (o *GrantIdentityPoolRoleUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role unprocessable entity response has a 4xx status code
func (o *GrantIdentityPoolRoleUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant identity pool role unprocessable entity response has a 5xx status code
func (o *GrantIdentityPoolRoleUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role unprocessable entity response a status code equal to that given
func (o *GrantIdentityPoolRoleUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the grant identity pool role unprocessable entity response
func (o *GrantIdentityPoolRoleUnprocessableEntity) Code() int {
	return 422
}

func (o *GrantIdentityPoolRoleUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GrantIdentityPoolRoleUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *GrantIdentityPoolRoleUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantIdentityPoolRoleUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGrantIdentityPoolRoleTooManyRequests creates a GrantIdentityPoolRoleTooManyRequests with default headers values
func NewGrantIdentityPoolRoleTooManyRequests() *GrantIdentityPoolRoleTooManyRequests {
	return &GrantIdentityPoolRoleTooManyRequests{}
}

/*
GrantIdentityPoolRoleTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GrantIdentityPoolRoleTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this grant identity pool role too many requests response has a 2xx status code
func (o *GrantIdentityPoolRoleTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this grant identity pool role too many requests response has a 3xx status code
func (o *GrantIdentityPoolRoleTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this grant identity pool role too many requests response has a 4xx status code
func (o *GrantIdentityPoolRoleTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this grant identity pool role too many requests response has a 5xx status code
func (o *GrantIdentityPoolRoleTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this grant identity pool role too many requests response a status code equal to that given
func (o *GrantIdentityPoolRoleTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the grant identity pool role too many requests response
func (o *GrantIdentityPoolRoleTooManyRequests) Code() int {
	return 429
}

func (o *GrantIdentityPoolRoleTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleTooManyRequests  %+v", 429, o.Payload)
}

func (o *GrantIdentityPoolRoleTooManyRequests) String() string {
	return fmt.Sprintf("[POST /pools/{ipID}/roles/grant][%d] grantIdentityPoolRoleTooManyRequests  %+v", 429, o.Payload)
}

func (o *GrantIdentityPoolRoleTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GrantIdentityPoolRoleTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}