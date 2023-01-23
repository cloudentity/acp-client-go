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

// SystemGetPoolReader is a Reader for the SystemGetPool structure.
type SystemGetPoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemGetPoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemGetPoolOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewSystemGetPoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemGetPoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemGetPoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemGetPoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSystemGetPoolOK creates a SystemGetPoolOK with default headers values
func NewSystemGetPoolOK() *SystemGetPoolOK {
	return &SystemGetPoolOK{}
}

/*
SystemGetPoolOK describes a response with status code 200, with default header values.

Identity Pool
*/
type SystemGetPoolOK struct {
	Payload *models.PoolResponse
}

// IsSuccess returns true when this system get pool o k response has a 2xx status code
func (o *SystemGetPoolOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system get pool o k response has a 3xx status code
func (o *SystemGetPoolOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get pool o k response has a 4xx status code
func (o *SystemGetPoolOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system get pool o k response has a 5xx status code
func (o *SystemGetPoolOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system get pool o k response a status code equal to that given
func (o *SystemGetPoolOK) IsCode(code int) bool {
	return code == 200
}

func (o *SystemGetPoolOK) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolOK  %+v", 200, o.Payload)
}

func (o *SystemGetPoolOK) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolOK  %+v", 200, o.Payload)
}

func (o *SystemGetPoolOK) GetPayload() *models.PoolResponse {
	return o.Payload
}

func (o *SystemGetPoolOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PoolResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetPoolUnauthorized creates a SystemGetPoolUnauthorized with default headers values
func NewSystemGetPoolUnauthorized() *SystemGetPoolUnauthorized {
	return &SystemGetPoolUnauthorized{}
}

/*
SystemGetPoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemGetPoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get pool unauthorized response has a 2xx status code
func (o *SystemGetPoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get pool unauthorized response has a 3xx status code
func (o *SystemGetPoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get pool unauthorized response has a 4xx status code
func (o *SystemGetPoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get pool unauthorized response has a 5xx status code
func (o *SystemGetPoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system get pool unauthorized response a status code equal to that given
func (o *SystemGetPoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *SystemGetPoolUnauthorized) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetPoolUnauthorized) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemGetPoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetPoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetPoolForbidden creates a SystemGetPoolForbidden with default headers values
func NewSystemGetPoolForbidden() *SystemGetPoolForbidden {
	return &SystemGetPoolForbidden{}
}

/*
SystemGetPoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemGetPoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get pool forbidden response has a 2xx status code
func (o *SystemGetPoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get pool forbidden response has a 3xx status code
func (o *SystemGetPoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get pool forbidden response has a 4xx status code
func (o *SystemGetPoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get pool forbidden response has a 5xx status code
func (o *SystemGetPoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system get pool forbidden response a status code equal to that given
func (o *SystemGetPoolForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *SystemGetPoolForbidden) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetPoolForbidden) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemGetPoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetPoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetPoolNotFound creates a SystemGetPoolNotFound with default headers values
func NewSystemGetPoolNotFound() *SystemGetPoolNotFound {
	return &SystemGetPoolNotFound{}
}

/*
SystemGetPoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemGetPoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get pool not found response has a 2xx status code
func (o *SystemGetPoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get pool not found response has a 3xx status code
func (o *SystemGetPoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get pool not found response has a 4xx status code
func (o *SystemGetPoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get pool not found response has a 5xx status code
func (o *SystemGetPoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system get pool not found response a status code equal to that given
func (o *SystemGetPoolNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *SystemGetPoolNotFound) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetPoolNotFound) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemGetPoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetPoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemGetPoolTooManyRequests creates a SystemGetPoolTooManyRequests with default headers values
func NewSystemGetPoolTooManyRequests() *SystemGetPoolTooManyRequests {
	return &SystemGetPoolTooManyRequests{}
}

/*
SystemGetPoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemGetPoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system get pool too many requests response has a 2xx status code
func (o *SystemGetPoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system get pool too many requests response has a 3xx status code
func (o *SystemGetPoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system get pool too many requests response has a 4xx status code
func (o *SystemGetPoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system get pool too many requests response has a 5xx status code
func (o *SystemGetPoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system get pool too many requests response a status code equal to that given
func (o *SystemGetPoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *SystemGetPoolTooManyRequests) Error() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetPoolTooManyRequests) String() string {
	return fmt.Sprintf("[GET /system/pools/{ipID}][%d] systemGetPoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemGetPoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemGetPoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
