// Code generated by go-swagger; DO NOT EDIT.

package limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// SetRateLimitReader is a Reader for the SetRateLimit structure.
type SetRateLimitReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetRateLimitReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSetRateLimitNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSetRateLimitUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetRateLimitForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetRateLimitNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetRateLimitTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSetRateLimitNoContent creates a SetRateLimitNoContent with default headers values
func NewSetRateLimitNoContent() *SetRateLimitNoContent {
	return &SetRateLimitNoContent{}
}

/*
SetRateLimitNoContent describes a response with status code 204, with default header values.

	custom rate limit has been saved
*/
type SetRateLimitNoContent struct {
}

// IsSuccess returns true when this set rate limit no content response has a 2xx status code
func (o *SetRateLimitNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set rate limit no content response has a 3xx status code
func (o *SetRateLimitNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set rate limit no content response has a 4xx status code
func (o *SetRateLimitNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this set rate limit no content response has a 5xx status code
func (o *SetRateLimitNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this set rate limit no content response a status code equal to that given
func (o *SetRateLimitNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the set rate limit no content response
func (o *SetRateLimitNoContent) Code() int {
	return 204
}

func (o *SetRateLimitNoContent) Error() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitNoContent ", 204)
}

func (o *SetRateLimitNoContent) String() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitNoContent ", 204)
}

func (o *SetRateLimitNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSetRateLimitUnauthorized creates a SetRateLimitUnauthorized with default headers values
func NewSetRateLimitUnauthorized() *SetRateLimitUnauthorized {
	return &SetRateLimitUnauthorized{}
}

/*
SetRateLimitUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetRateLimitUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set rate limit unauthorized response has a 2xx status code
func (o *SetRateLimitUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set rate limit unauthorized response has a 3xx status code
func (o *SetRateLimitUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set rate limit unauthorized response has a 4xx status code
func (o *SetRateLimitUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set rate limit unauthorized response has a 5xx status code
func (o *SetRateLimitUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set rate limit unauthorized response a status code equal to that given
func (o *SetRateLimitUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set rate limit unauthorized response
func (o *SetRateLimitUnauthorized) Code() int {
	return 401
}

func (o *SetRateLimitUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitUnauthorized  %+v", 401, o.Payload)
}

func (o *SetRateLimitUnauthorized) String() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitUnauthorized  %+v", 401, o.Payload)
}

func (o *SetRateLimitUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetRateLimitUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetRateLimitForbidden creates a SetRateLimitForbidden with default headers values
func NewSetRateLimitForbidden() *SetRateLimitForbidden {
	return &SetRateLimitForbidden{}
}

/*
SetRateLimitForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetRateLimitForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set rate limit forbidden response has a 2xx status code
func (o *SetRateLimitForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set rate limit forbidden response has a 3xx status code
func (o *SetRateLimitForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set rate limit forbidden response has a 4xx status code
func (o *SetRateLimitForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set rate limit forbidden response has a 5xx status code
func (o *SetRateLimitForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set rate limit forbidden response a status code equal to that given
func (o *SetRateLimitForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set rate limit forbidden response
func (o *SetRateLimitForbidden) Code() int {
	return 403
}

func (o *SetRateLimitForbidden) Error() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitForbidden  %+v", 403, o.Payload)
}

func (o *SetRateLimitForbidden) String() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitForbidden  %+v", 403, o.Payload)
}

func (o *SetRateLimitForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetRateLimitForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetRateLimitNotFound creates a SetRateLimitNotFound with default headers values
func NewSetRateLimitNotFound() *SetRateLimitNotFound {
	return &SetRateLimitNotFound{}
}

/*
SetRateLimitNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetRateLimitNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set rate limit not found response has a 2xx status code
func (o *SetRateLimitNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set rate limit not found response has a 3xx status code
func (o *SetRateLimitNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set rate limit not found response has a 4xx status code
func (o *SetRateLimitNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set rate limit not found response has a 5xx status code
func (o *SetRateLimitNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set rate limit not found response a status code equal to that given
func (o *SetRateLimitNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set rate limit not found response
func (o *SetRateLimitNotFound) Code() int {
	return 404
}

func (o *SetRateLimitNotFound) Error() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitNotFound  %+v", 404, o.Payload)
}

func (o *SetRateLimitNotFound) String() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitNotFound  %+v", 404, o.Payload)
}

func (o *SetRateLimitNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetRateLimitNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetRateLimitTooManyRequests creates a SetRateLimitTooManyRequests with default headers values
func NewSetRateLimitTooManyRequests() *SetRateLimitTooManyRequests {
	return &SetRateLimitTooManyRequests{}
}

/*
SetRateLimitTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SetRateLimitTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set rate limit too many requests response has a 2xx status code
func (o *SetRateLimitTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set rate limit too many requests response has a 3xx status code
func (o *SetRateLimitTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set rate limit too many requests response has a 4xx status code
func (o *SetRateLimitTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set rate limit too many requests response has a 5xx status code
func (o *SetRateLimitTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set rate limit too many requests response a status code equal to that given
func (o *SetRateLimitTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set rate limit too many requests response
func (o *SetRateLimitTooManyRequests) Code() int {
	return 429
}

func (o *SetRateLimitTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetRateLimitTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /api/admin/tenants/{tid}/rate-limits/{module}][%d] setRateLimitTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetRateLimitTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetRateLimitTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
