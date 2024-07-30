// Code generated by go-swagger; DO NOT EDIT.

package security

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// SetTenantSecurityReader is a Reader for the SetTenantSecurity structure.
type SetTenantSecurityReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetTenantSecurityReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSetTenantSecurityNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetTenantSecurityBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSetTenantSecurityUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetTenantSecurityForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetTenantSecurityNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetTenantSecurityUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetTenantSecurityTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/admin/tenants/{tid}/security] setTenantSecurity", response, response.Code())
	}
}

// NewSetTenantSecurityNoContent creates a SetTenantSecurityNoContent with default headers values
func NewSetTenantSecurityNoContent() *SetTenantSecurityNoContent {
	return &SetTenantSecurityNoContent{}
}

/*
SetTenantSecurityNoContent describes a response with status code 204, with default header values.

	tenant feature set
*/
type SetTenantSecurityNoContent struct {
}

// IsSuccess returns true when this set tenant security no content response has a 2xx status code
func (o *SetTenantSecurityNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set tenant security no content response has a 3xx status code
func (o *SetTenantSecurityNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security no content response has a 4xx status code
func (o *SetTenantSecurityNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this set tenant security no content response has a 5xx status code
func (o *SetTenantSecurityNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security no content response a status code equal to that given
func (o *SetTenantSecurityNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the set tenant security no content response
func (o *SetTenantSecurityNoContent) Code() int {
	return 204
}

func (o *SetTenantSecurityNoContent) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityNoContent ", 204)
}

func (o *SetTenantSecurityNoContent) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityNoContent ", 204)
}

func (o *SetTenantSecurityNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSetTenantSecurityBadRequest creates a SetTenantSecurityBadRequest with default headers values
func NewSetTenantSecurityBadRequest() *SetTenantSecurityBadRequest {
	return &SetTenantSecurityBadRequest{}
}

/*
SetTenantSecurityBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SetTenantSecurityBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security bad request response has a 2xx status code
func (o *SetTenantSecurityBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security bad request response has a 3xx status code
func (o *SetTenantSecurityBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security bad request response has a 4xx status code
func (o *SetTenantSecurityBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security bad request response has a 5xx status code
func (o *SetTenantSecurityBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security bad request response a status code equal to that given
func (o *SetTenantSecurityBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set tenant security bad request response
func (o *SetTenantSecurityBadRequest) Code() int {
	return 400
}

func (o *SetTenantSecurityBadRequest) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityBadRequest  %+v", 400, o.Payload)
}

func (o *SetTenantSecurityBadRequest) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityBadRequest  %+v", 400, o.Payload)
}

func (o *SetTenantSecurityBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetTenantSecurityUnauthorized creates a SetTenantSecurityUnauthorized with default headers values
func NewSetTenantSecurityUnauthorized() *SetTenantSecurityUnauthorized {
	return &SetTenantSecurityUnauthorized{}
}

/*
SetTenantSecurityUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetTenantSecurityUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security unauthorized response has a 2xx status code
func (o *SetTenantSecurityUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security unauthorized response has a 3xx status code
func (o *SetTenantSecurityUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security unauthorized response has a 4xx status code
func (o *SetTenantSecurityUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security unauthorized response has a 5xx status code
func (o *SetTenantSecurityUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security unauthorized response a status code equal to that given
func (o *SetTenantSecurityUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set tenant security unauthorized response
func (o *SetTenantSecurityUnauthorized) Code() int {
	return 401
}

func (o *SetTenantSecurityUnauthorized) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityUnauthorized  %+v", 401, o.Payload)
}

func (o *SetTenantSecurityUnauthorized) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityUnauthorized  %+v", 401, o.Payload)
}

func (o *SetTenantSecurityUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetTenantSecurityForbidden creates a SetTenantSecurityForbidden with default headers values
func NewSetTenantSecurityForbidden() *SetTenantSecurityForbidden {
	return &SetTenantSecurityForbidden{}
}

/*
SetTenantSecurityForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetTenantSecurityForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security forbidden response has a 2xx status code
func (o *SetTenantSecurityForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security forbidden response has a 3xx status code
func (o *SetTenantSecurityForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security forbidden response has a 4xx status code
func (o *SetTenantSecurityForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security forbidden response has a 5xx status code
func (o *SetTenantSecurityForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security forbidden response a status code equal to that given
func (o *SetTenantSecurityForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set tenant security forbidden response
func (o *SetTenantSecurityForbidden) Code() int {
	return 403
}

func (o *SetTenantSecurityForbidden) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityForbidden  %+v", 403, o.Payload)
}

func (o *SetTenantSecurityForbidden) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityForbidden  %+v", 403, o.Payload)
}

func (o *SetTenantSecurityForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetTenantSecurityNotFound creates a SetTenantSecurityNotFound with default headers values
func NewSetTenantSecurityNotFound() *SetTenantSecurityNotFound {
	return &SetTenantSecurityNotFound{}
}

/*
SetTenantSecurityNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetTenantSecurityNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security not found response has a 2xx status code
func (o *SetTenantSecurityNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security not found response has a 3xx status code
func (o *SetTenantSecurityNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security not found response has a 4xx status code
func (o *SetTenantSecurityNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security not found response has a 5xx status code
func (o *SetTenantSecurityNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security not found response a status code equal to that given
func (o *SetTenantSecurityNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set tenant security not found response
func (o *SetTenantSecurityNotFound) Code() int {
	return 404
}

func (o *SetTenantSecurityNotFound) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityNotFound  %+v", 404, o.Payload)
}

func (o *SetTenantSecurityNotFound) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityNotFound  %+v", 404, o.Payload)
}

func (o *SetTenantSecurityNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetTenantSecurityUnprocessableEntity creates a SetTenantSecurityUnprocessableEntity with default headers values
func NewSetTenantSecurityUnprocessableEntity() *SetTenantSecurityUnprocessableEntity {
	return &SetTenantSecurityUnprocessableEntity{}
}

/*
SetTenantSecurityUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SetTenantSecurityUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security unprocessable entity response has a 2xx status code
func (o *SetTenantSecurityUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security unprocessable entity response has a 3xx status code
func (o *SetTenantSecurityUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security unprocessable entity response has a 4xx status code
func (o *SetTenantSecurityUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security unprocessable entity response has a 5xx status code
func (o *SetTenantSecurityUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security unprocessable entity response a status code equal to that given
func (o *SetTenantSecurityUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the set tenant security unprocessable entity response
func (o *SetTenantSecurityUnprocessableEntity) Code() int {
	return 422
}

func (o *SetTenantSecurityUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetTenantSecurityUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetTenantSecurityUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetTenantSecurityTooManyRequests creates a SetTenantSecurityTooManyRequests with default headers values
func NewSetTenantSecurityTooManyRequests() *SetTenantSecurityTooManyRequests {
	return &SetTenantSecurityTooManyRequests{}
}

/*
SetTenantSecurityTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SetTenantSecurityTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set tenant security too many requests response has a 2xx status code
func (o *SetTenantSecurityTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set tenant security too many requests response has a 3xx status code
func (o *SetTenantSecurityTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set tenant security too many requests response has a 4xx status code
func (o *SetTenantSecurityTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set tenant security too many requests response has a 5xx status code
func (o *SetTenantSecurityTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set tenant security too many requests response a status code equal to that given
func (o *SetTenantSecurityTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set tenant security too many requests response
func (o *SetTenantSecurityTooManyRequests) Code() int {
	return 429
}

func (o *SetTenantSecurityTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetTenantSecurityTooManyRequests) String() string {
	return fmt.Sprintf("[POST /api/admin/tenants/{tid}/security][%d] setTenantSecurityTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetTenantSecurityTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetTenantSecurityTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}