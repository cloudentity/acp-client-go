// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemDeletePoolReader is a Reader for the SystemDeletePool structure.
type SystemDeletePoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemDeletePoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSystemDeletePoolNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemDeletePoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemDeletePoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemDeletePoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemDeletePoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /system/pools/{ipID}] systemDeletePool", response, response.Code())
	}
}

// NewSystemDeletePoolNoContent creates a SystemDeletePoolNoContent with default headers values
func NewSystemDeletePoolNoContent() *SystemDeletePoolNoContent {
	return &SystemDeletePoolNoContent{}
}

/*
SystemDeletePoolNoContent describes a response with status code 204, with default header values.

	Identity Pool Deleted
*/
type SystemDeletePoolNoContent struct {
}

// IsSuccess returns true when this system delete pool no content response has a 2xx status code
func (o *SystemDeletePoolNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system delete pool no content response has a 3xx status code
func (o *SystemDeletePoolNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete pool no content response has a 4xx status code
func (o *SystemDeletePoolNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this system delete pool no content response has a 5xx status code
func (o *SystemDeletePoolNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete pool no content response a status code equal to that given
func (o *SystemDeletePoolNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the system delete pool no content response
func (o *SystemDeletePoolNoContent) Code() int {
	return 204
}

func (o *SystemDeletePoolNoContent) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolNoContent ", 204)
}

func (o *SystemDeletePoolNoContent) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolNoContent ", 204)
}

func (o *SystemDeletePoolNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSystemDeletePoolUnauthorized creates a SystemDeletePoolUnauthorized with default headers values
func NewSystemDeletePoolUnauthorized() *SystemDeletePoolUnauthorized {
	return &SystemDeletePoolUnauthorized{}
}

/*
SystemDeletePoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemDeletePoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete pool unauthorized response has a 2xx status code
func (o *SystemDeletePoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete pool unauthorized response has a 3xx status code
func (o *SystemDeletePoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete pool unauthorized response has a 4xx status code
func (o *SystemDeletePoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete pool unauthorized response has a 5xx status code
func (o *SystemDeletePoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete pool unauthorized response a status code equal to that given
func (o *SystemDeletePoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system delete pool unauthorized response
func (o *SystemDeletePoolUnauthorized) Code() int {
	return 401
}

func (o *SystemDeletePoolUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeletePoolUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemDeletePoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeletePoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeletePoolForbidden creates a SystemDeletePoolForbidden with default headers values
func NewSystemDeletePoolForbidden() *SystemDeletePoolForbidden {
	return &SystemDeletePoolForbidden{}
}

/*
SystemDeletePoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemDeletePoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete pool forbidden response has a 2xx status code
func (o *SystemDeletePoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete pool forbidden response has a 3xx status code
func (o *SystemDeletePoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete pool forbidden response has a 4xx status code
func (o *SystemDeletePoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete pool forbidden response has a 5xx status code
func (o *SystemDeletePoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete pool forbidden response a status code equal to that given
func (o *SystemDeletePoolForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system delete pool forbidden response
func (o *SystemDeletePoolForbidden) Code() int {
	return 403
}

func (o *SystemDeletePoolForbidden) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeletePoolForbidden) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemDeletePoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeletePoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeletePoolNotFound creates a SystemDeletePoolNotFound with default headers values
func NewSystemDeletePoolNotFound() *SystemDeletePoolNotFound {
	return &SystemDeletePoolNotFound{}
}

/*
SystemDeletePoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemDeletePoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete pool not found response has a 2xx status code
func (o *SystemDeletePoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete pool not found response has a 3xx status code
func (o *SystemDeletePoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete pool not found response has a 4xx status code
func (o *SystemDeletePoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete pool not found response has a 5xx status code
func (o *SystemDeletePoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete pool not found response a status code equal to that given
func (o *SystemDeletePoolNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the system delete pool not found response
func (o *SystemDeletePoolNotFound) Code() int {
	return 404
}

func (o *SystemDeletePoolNotFound) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeletePoolNotFound) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemDeletePoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeletePoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemDeletePoolTooManyRequests creates a SystemDeletePoolTooManyRequests with default headers values
func NewSystemDeletePoolTooManyRequests() *SystemDeletePoolTooManyRequests {
	return &SystemDeletePoolTooManyRequests{}
}

/*
SystemDeletePoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemDeletePoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system delete pool too many requests response has a 2xx status code
func (o *SystemDeletePoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system delete pool too many requests response has a 3xx status code
func (o *SystemDeletePoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system delete pool too many requests response has a 4xx status code
func (o *SystemDeletePoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system delete pool too many requests response has a 5xx status code
func (o *SystemDeletePoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system delete pool too many requests response a status code equal to that given
func (o *SystemDeletePoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system delete pool too many requests response
func (o *SystemDeletePoolTooManyRequests) Code() int {
	return 429
}

func (o *SystemDeletePoolTooManyRequests) Error() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeletePoolTooManyRequests) String() string {
	return fmt.Sprintf("[DELETE /system/pools/{ipID}][%d] systemDeletePoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemDeletePoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemDeletePoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
