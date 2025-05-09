// Code generated by go-swagger; DO NOT EDIT.

package limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// DeleteRateLimitReader is a Reader for the DeleteRateLimit structure.
type DeleteRateLimitReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteRateLimitReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewDeleteRateLimitNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDeleteRateLimitUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewDeleteRateLimitForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteRateLimitNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewDeleteRateLimitTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}] deleteRateLimit", response, response.Code())
	}
}

// NewDeleteRateLimitNoContent creates a DeleteRateLimitNoContent with default headers values
func NewDeleteRateLimitNoContent() *DeleteRateLimitNoContent {
	return &DeleteRateLimitNoContent{}
}

/*
DeleteRateLimitNoContent describes a response with status code 204, with default header values.

	custom rate limit has been deleted
*/
type DeleteRateLimitNoContent struct {
}

// IsSuccess returns true when this delete rate limit no content response has a 2xx status code
func (o *DeleteRateLimitNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete rate limit no content response has a 3xx status code
func (o *DeleteRateLimitNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rate limit no content response has a 4xx status code
func (o *DeleteRateLimitNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete rate limit no content response has a 5xx status code
func (o *DeleteRateLimitNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rate limit no content response a status code equal to that given
func (o *DeleteRateLimitNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the delete rate limit no content response
func (o *DeleteRateLimitNoContent) Code() int {
	return 204
}

func (o *DeleteRateLimitNoContent) Error() string {
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitNoContent", 204)
}

func (o *DeleteRateLimitNoContent) String() string {
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitNoContent", 204)
}

func (o *DeleteRateLimitNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeleteRateLimitUnauthorized creates a DeleteRateLimitUnauthorized with default headers values
func NewDeleteRateLimitUnauthorized() *DeleteRateLimitUnauthorized {
	return &DeleteRateLimitUnauthorized{}
}

/*
DeleteRateLimitUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteRateLimitUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete rate limit unauthorized response has a 2xx status code
func (o *DeleteRateLimitUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rate limit unauthorized response has a 3xx status code
func (o *DeleteRateLimitUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rate limit unauthorized response has a 4xx status code
func (o *DeleteRateLimitUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rate limit unauthorized response has a 5xx status code
func (o *DeleteRateLimitUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rate limit unauthorized response a status code equal to that given
func (o *DeleteRateLimitUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete rate limit unauthorized response
func (o *DeleteRateLimitUnauthorized) Code() int {
	return 401
}

func (o *DeleteRateLimitUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitUnauthorized %s", 401, payload)
}

func (o *DeleteRateLimitUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitUnauthorized %s", 401, payload)
}

func (o *DeleteRateLimitUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteRateLimitUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRateLimitForbidden creates a DeleteRateLimitForbidden with default headers values
func NewDeleteRateLimitForbidden() *DeleteRateLimitForbidden {
	return &DeleteRateLimitForbidden{}
}

/*
DeleteRateLimitForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type DeleteRateLimitForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete rate limit forbidden response has a 2xx status code
func (o *DeleteRateLimitForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rate limit forbidden response has a 3xx status code
func (o *DeleteRateLimitForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rate limit forbidden response has a 4xx status code
func (o *DeleteRateLimitForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rate limit forbidden response has a 5xx status code
func (o *DeleteRateLimitForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rate limit forbidden response a status code equal to that given
func (o *DeleteRateLimitForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the delete rate limit forbidden response
func (o *DeleteRateLimitForbidden) Code() int {
	return 403
}

func (o *DeleteRateLimitForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitForbidden %s", 403, payload)
}

func (o *DeleteRateLimitForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitForbidden %s", 403, payload)
}

func (o *DeleteRateLimitForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteRateLimitForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRateLimitNotFound creates a DeleteRateLimitNotFound with default headers values
func NewDeleteRateLimitNotFound() *DeleteRateLimitNotFound {
	return &DeleteRateLimitNotFound{}
}

/*
DeleteRateLimitNotFound describes a response with status code 404, with default header values.

Not found
*/
type DeleteRateLimitNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete rate limit not found response has a 2xx status code
func (o *DeleteRateLimitNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rate limit not found response has a 3xx status code
func (o *DeleteRateLimitNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rate limit not found response has a 4xx status code
func (o *DeleteRateLimitNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rate limit not found response has a 5xx status code
func (o *DeleteRateLimitNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rate limit not found response a status code equal to that given
func (o *DeleteRateLimitNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete rate limit not found response
func (o *DeleteRateLimitNotFound) Code() int {
	return 404
}

func (o *DeleteRateLimitNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitNotFound %s", 404, payload)
}

func (o *DeleteRateLimitNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitNotFound %s", 404, payload)
}

func (o *DeleteRateLimitNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteRateLimitNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteRateLimitTooManyRequests creates a DeleteRateLimitTooManyRequests with default headers values
func NewDeleteRateLimitTooManyRequests() *DeleteRateLimitTooManyRequests {
	return &DeleteRateLimitTooManyRequests{}
}

/*
DeleteRateLimitTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type DeleteRateLimitTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this delete rate limit too many requests response has a 2xx status code
func (o *DeleteRateLimitTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete rate limit too many requests response has a 3xx status code
func (o *DeleteRateLimitTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete rate limit too many requests response has a 4xx status code
func (o *DeleteRateLimitTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete rate limit too many requests response has a 5xx status code
func (o *DeleteRateLimitTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this delete rate limit too many requests response a status code equal to that given
func (o *DeleteRateLimitTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the delete rate limit too many requests response
func (o *DeleteRateLimitTooManyRequests) Code() int {
	return 429
}

func (o *DeleteRateLimitTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitTooManyRequests %s", 429, payload)
}

func (o *DeleteRateLimitTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /api/admin/tenants/{tid}/rate-limits/{module}][%d] deleteRateLimitTooManyRequests %s", 429, payload)
}

func (o *DeleteRateLimitTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeleteRateLimitTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
