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

// SystemCreatePoolReader is a Reader for the SystemCreatePool structure.
type SystemCreatePoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemCreatePoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewSystemCreatePoolCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemCreatePoolBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemCreatePoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemCreatePoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemCreatePoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSystemCreatePoolConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemCreatePoolUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemCreatePoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /system/pools] systemCreatePool", response, response.Code())
	}
}

// NewSystemCreatePoolCreated creates a SystemCreatePoolCreated with default headers values
func NewSystemCreatePoolCreated() *SystemCreatePoolCreated {
	return &SystemCreatePoolCreated{}
}

/*
SystemCreatePoolCreated describes a response with status code 201, with default header values.

Identity Pool
*/
type SystemCreatePoolCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.PoolResponse
}

// IsSuccess returns true when this system create pool created response has a 2xx status code
func (o *SystemCreatePoolCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system create pool created response has a 3xx status code
func (o *SystemCreatePoolCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool created response has a 4xx status code
func (o *SystemCreatePoolCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this system create pool created response has a 5xx status code
func (o *SystemCreatePoolCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool created response a status code equal to that given
func (o *SystemCreatePoolCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the system create pool created response
func (o *SystemCreatePoolCreated) Code() int {
	return 201
}

func (o *SystemCreatePoolCreated) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolCreated  %+v", 201, o.Payload)
}

func (o *SystemCreatePoolCreated) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolCreated  %+v", 201, o.Payload)
}

func (o *SystemCreatePoolCreated) GetPayload() *models.PoolResponse {
	return o.Payload
}

func (o *SystemCreatePoolCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.PoolResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolBadRequest creates a SystemCreatePoolBadRequest with default headers values
func NewSystemCreatePoolBadRequest() *SystemCreatePoolBadRequest {
	return &SystemCreatePoolBadRequest{}
}

/*
SystemCreatePoolBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SystemCreatePoolBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool bad request response has a 2xx status code
func (o *SystemCreatePoolBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool bad request response has a 3xx status code
func (o *SystemCreatePoolBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool bad request response has a 4xx status code
func (o *SystemCreatePoolBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool bad request response has a 5xx status code
func (o *SystemCreatePoolBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool bad request response a status code equal to that given
func (o *SystemCreatePoolBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the system create pool bad request response
func (o *SystemCreatePoolBadRequest) Code() int {
	return 400
}

func (o *SystemCreatePoolBadRequest) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolBadRequest  %+v", 400, o.Payload)
}

func (o *SystemCreatePoolBadRequest) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolBadRequest  %+v", 400, o.Payload)
}

func (o *SystemCreatePoolBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolUnauthorized creates a SystemCreatePoolUnauthorized with default headers values
func NewSystemCreatePoolUnauthorized() *SystemCreatePoolUnauthorized {
	return &SystemCreatePoolUnauthorized{}
}

/*
SystemCreatePoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemCreatePoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool unauthorized response has a 2xx status code
func (o *SystemCreatePoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool unauthorized response has a 3xx status code
func (o *SystemCreatePoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool unauthorized response has a 4xx status code
func (o *SystemCreatePoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool unauthorized response has a 5xx status code
func (o *SystemCreatePoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool unauthorized response a status code equal to that given
func (o *SystemCreatePoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system create pool unauthorized response
func (o *SystemCreatePoolUnauthorized) Code() int {
	return 401
}

func (o *SystemCreatePoolUnauthorized) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemCreatePoolUnauthorized) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolUnauthorized  %+v", 401, o.Payload)
}

func (o *SystemCreatePoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolForbidden creates a SystemCreatePoolForbidden with default headers values
func NewSystemCreatePoolForbidden() *SystemCreatePoolForbidden {
	return &SystemCreatePoolForbidden{}
}

/*
SystemCreatePoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemCreatePoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool forbidden response has a 2xx status code
func (o *SystemCreatePoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool forbidden response has a 3xx status code
func (o *SystemCreatePoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool forbidden response has a 4xx status code
func (o *SystemCreatePoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool forbidden response has a 5xx status code
func (o *SystemCreatePoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool forbidden response a status code equal to that given
func (o *SystemCreatePoolForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system create pool forbidden response
func (o *SystemCreatePoolForbidden) Code() int {
	return 403
}

func (o *SystemCreatePoolForbidden) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemCreatePoolForbidden) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolForbidden  %+v", 403, o.Payload)
}

func (o *SystemCreatePoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolNotFound creates a SystemCreatePoolNotFound with default headers values
func NewSystemCreatePoolNotFound() *SystemCreatePoolNotFound {
	return &SystemCreatePoolNotFound{}
}

/*
SystemCreatePoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemCreatePoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool not found response has a 2xx status code
func (o *SystemCreatePoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool not found response has a 3xx status code
func (o *SystemCreatePoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool not found response has a 4xx status code
func (o *SystemCreatePoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool not found response has a 5xx status code
func (o *SystemCreatePoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool not found response a status code equal to that given
func (o *SystemCreatePoolNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the system create pool not found response
func (o *SystemCreatePoolNotFound) Code() int {
	return 404
}

func (o *SystemCreatePoolNotFound) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemCreatePoolNotFound) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolNotFound  %+v", 404, o.Payload)
}

func (o *SystemCreatePoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolConflict creates a SystemCreatePoolConflict with default headers values
func NewSystemCreatePoolConflict() *SystemCreatePoolConflict {
	return &SystemCreatePoolConflict{}
}

/*
SystemCreatePoolConflict describes a response with status code 409, with default header values.

Conflict
*/
type SystemCreatePoolConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool conflict response has a 2xx status code
func (o *SystemCreatePoolConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool conflict response has a 3xx status code
func (o *SystemCreatePoolConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool conflict response has a 4xx status code
func (o *SystemCreatePoolConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool conflict response has a 5xx status code
func (o *SystemCreatePoolConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool conflict response a status code equal to that given
func (o *SystemCreatePoolConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the system create pool conflict response
func (o *SystemCreatePoolConflict) Code() int {
	return 409
}

func (o *SystemCreatePoolConflict) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolConflict  %+v", 409, o.Payload)
}

func (o *SystemCreatePoolConflict) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolConflict  %+v", 409, o.Payload)
}

func (o *SystemCreatePoolConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolUnprocessableEntity creates a SystemCreatePoolUnprocessableEntity with default headers values
func NewSystemCreatePoolUnprocessableEntity() *SystemCreatePoolUnprocessableEntity {
	return &SystemCreatePoolUnprocessableEntity{}
}

/*
SystemCreatePoolUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SystemCreatePoolUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool unprocessable entity response has a 2xx status code
func (o *SystemCreatePoolUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool unprocessable entity response has a 3xx status code
func (o *SystemCreatePoolUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool unprocessable entity response has a 4xx status code
func (o *SystemCreatePoolUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool unprocessable entity response has a 5xx status code
func (o *SystemCreatePoolUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool unprocessable entity response a status code equal to that given
func (o *SystemCreatePoolUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the system create pool unprocessable entity response
func (o *SystemCreatePoolUnprocessableEntity) Code() int {
	return 422
}

func (o *SystemCreatePoolUnprocessableEntity) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemCreatePoolUnprocessableEntity) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SystemCreatePoolUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemCreatePoolTooManyRequests creates a SystemCreatePoolTooManyRequests with default headers values
func NewSystemCreatePoolTooManyRequests() *SystemCreatePoolTooManyRequests {
	return &SystemCreatePoolTooManyRequests{}
}

/*
SystemCreatePoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemCreatePoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system create pool too many requests response has a 2xx status code
func (o *SystemCreatePoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system create pool too many requests response has a 3xx status code
func (o *SystemCreatePoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system create pool too many requests response has a 4xx status code
func (o *SystemCreatePoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system create pool too many requests response has a 5xx status code
func (o *SystemCreatePoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system create pool too many requests response a status code equal to that given
func (o *SystemCreatePoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system create pool too many requests response
func (o *SystemCreatePoolTooManyRequests) Code() int {
	return 429
}

func (o *SystemCreatePoolTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemCreatePoolTooManyRequests) String() string {
	return fmt.Sprintf("[POST /system/pools][%d] systemCreatePoolTooManyRequests  %+v", 429, o.Payload)
}

func (o *SystemCreatePoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemCreatePoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
