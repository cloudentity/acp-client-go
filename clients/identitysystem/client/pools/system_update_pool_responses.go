// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// SystemUpdatePoolReader is a Reader for the SystemUpdatePool structure.
type SystemUpdatePoolReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SystemUpdatePoolReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSystemUpdatePoolOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSystemUpdatePoolBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSystemUpdatePoolUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSystemUpdatePoolForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSystemUpdatePoolNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSystemUpdatePoolConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSystemUpdatePoolUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSystemUpdatePoolTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /system/pools/{ipID}] systemUpdatePool", response, response.Code())
	}
}

// NewSystemUpdatePoolOK creates a SystemUpdatePoolOK with default headers values
func NewSystemUpdatePoolOK() *SystemUpdatePoolOK {
	return &SystemUpdatePoolOK{}
}

/*
SystemUpdatePoolOK describes a response with status code 200, with default header values.

Identity Pool
*/
type SystemUpdatePoolOK struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.PoolResponse
}

// IsSuccess returns true when this system update pool o k response has a 2xx status code
func (o *SystemUpdatePoolOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this system update pool o k response has a 3xx status code
func (o *SystemUpdatePoolOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool o k response has a 4xx status code
func (o *SystemUpdatePoolOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this system update pool o k response has a 5xx status code
func (o *SystemUpdatePoolOK) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool o k response a status code equal to that given
func (o *SystemUpdatePoolOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the system update pool o k response
func (o *SystemUpdatePoolOK) Code() int {
	return 200
}

func (o *SystemUpdatePoolOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolOK %s", 200, payload)
}

func (o *SystemUpdatePoolOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolOK %s", 200, payload)
}

func (o *SystemUpdatePoolOK) GetPayload() *models.PoolResponse {
	return o.Payload
}

func (o *SystemUpdatePoolOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewSystemUpdatePoolBadRequest creates a SystemUpdatePoolBadRequest with default headers values
func NewSystemUpdatePoolBadRequest() *SystemUpdatePoolBadRequest {
	return &SystemUpdatePoolBadRequest{}
}

/*
SystemUpdatePoolBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SystemUpdatePoolBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool bad request response has a 2xx status code
func (o *SystemUpdatePoolBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool bad request response has a 3xx status code
func (o *SystemUpdatePoolBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool bad request response has a 4xx status code
func (o *SystemUpdatePoolBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool bad request response has a 5xx status code
func (o *SystemUpdatePoolBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool bad request response a status code equal to that given
func (o *SystemUpdatePoolBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the system update pool bad request response
func (o *SystemUpdatePoolBadRequest) Code() int {
	return 400
}

func (o *SystemUpdatePoolBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolBadRequest %s", 400, payload)
}

func (o *SystemUpdatePoolBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolBadRequest %s", 400, payload)
}

func (o *SystemUpdatePoolBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolUnauthorized creates a SystemUpdatePoolUnauthorized with default headers values
func NewSystemUpdatePoolUnauthorized() *SystemUpdatePoolUnauthorized {
	return &SystemUpdatePoolUnauthorized{}
}

/*
SystemUpdatePoolUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SystemUpdatePoolUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool unauthorized response has a 2xx status code
func (o *SystemUpdatePoolUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool unauthorized response has a 3xx status code
func (o *SystemUpdatePoolUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool unauthorized response has a 4xx status code
func (o *SystemUpdatePoolUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool unauthorized response has a 5xx status code
func (o *SystemUpdatePoolUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool unauthorized response a status code equal to that given
func (o *SystemUpdatePoolUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the system update pool unauthorized response
func (o *SystemUpdatePoolUnauthorized) Code() int {
	return 401
}

func (o *SystemUpdatePoolUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolUnauthorized %s", 401, payload)
}

func (o *SystemUpdatePoolUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolUnauthorized %s", 401, payload)
}

func (o *SystemUpdatePoolUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolForbidden creates a SystemUpdatePoolForbidden with default headers values
func NewSystemUpdatePoolForbidden() *SystemUpdatePoolForbidden {
	return &SystemUpdatePoolForbidden{}
}

/*
SystemUpdatePoolForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SystemUpdatePoolForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool forbidden response has a 2xx status code
func (o *SystemUpdatePoolForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool forbidden response has a 3xx status code
func (o *SystemUpdatePoolForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool forbidden response has a 4xx status code
func (o *SystemUpdatePoolForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool forbidden response has a 5xx status code
func (o *SystemUpdatePoolForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool forbidden response a status code equal to that given
func (o *SystemUpdatePoolForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the system update pool forbidden response
func (o *SystemUpdatePoolForbidden) Code() int {
	return 403
}

func (o *SystemUpdatePoolForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolForbidden %s", 403, payload)
}

func (o *SystemUpdatePoolForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolForbidden %s", 403, payload)
}

func (o *SystemUpdatePoolForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolNotFound creates a SystemUpdatePoolNotFound with default headers values
func NewSystemUpdatePoolNotFound() *SystemUpdatePoolNotFound {
	return &SystemUpdatePoolNotFound{}
}

/*
SystemUpdatePoolNotFound describes a response with status code 404, with default header values.

Not found
*/
type SystemUpdatePoolNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool not found response has a 2xx status code
func (o *SystemUpdatePoolNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool not found response has a 3xx status code
func (o *SystemUpdatePoolNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool not found response has a 4xx status code
func (o *SystemUpdatePoolNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool not found response has a 5xx status code
func (o *SystemUpdatePoolNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool not found response a status code equal to that given
func (o *SystemUpdatePoolNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the system update pool not found response
func (o *SystemUpdatePoolNotFound) Code() int {
	return 404
}

func (o *SystemUpdatePoolNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolNotFound %s", 404, payload)
}

func (o *SystemUpdatePoolNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolNotFound %s", 404, payload)
}

func (o *SystemUpdatePoolNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolConflict creates a SystemUpdatePoolConflict with default headers values
func NewSystemUpdatePoolConflict() *SystemUpdatePoolConflict {
	return &SystemUpdatePoolConflict{}
}

/*
SystemUpdatePoolConflict describes a response with status code 409, with default header values.

Conflict
*/
type SystemUpdatePoolConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool conflict response has a 2xx status code
func (o *SystemUpdatePoolConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool conflict response has a 3xx status code
func (o *SystemUpdatePoolConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool conflict response has a 4xx status code
func (o *SystemUpdatePoolConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool conflict response has a 5xx status code
func (o *SystemUpdatePoolConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool conflict response a status code equal to that given
func (o *SystemUpdatePoolConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the system update pool conflict response
func (o *SystemUpdatePoolConflict) Code() int {
	return 409
}

func (o *SystemUpdatePoolConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolConflict %s", 409, payload)
}

func (o *SystemUpdatePoolConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolConflict %s", 409, payload)
}

func (o *SystemUpdatePoolConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolUnprocessableEntity creates a SystemUpdatePoolUnprocessableEntity with default headers values
func NewSystemUpdatePoolUnprocessableEntity() *SystemUpdatePoolUnprocessableEntity {
	return &SystemUpdatePoolUnprocessableEntity{}
}

/*
SystemUpdatePoolUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SystemUpdatePoolUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool unprocessable entity response has a 2xx status code
func (o *SystemUpdatePoolUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool unprocessable entity response has a 3xx status code
func (o *SystemUpdatePoolUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool unprocessable entity response has a 4xx status code
func (o *SystemUpdatePoolUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool unprocessable entity response has a 5xx status code
func (o *SystemUpdatePoolUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool unprocessable entity response a status code equal to that given
func (o *SystemUpdatePoolUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the system update pool unprocessable entity response
func (o *SystemUpdatePoolUnprocessableEntity) Code() int {
	return 422
}

func (o *SystemUpdatePoolUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolUnprocessableEntity %s", 422, payload)
}

func (o *SystemUpdatePoolUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolUnprocessableEntity %s", 422, payload)
}

func (o *SystemUpdatePoolUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSystemUpdatePoolTooManyRequests creates a SystemUpdatePoolTooManyRequests with default headers values
func NewSystemUpdatePoolTooManyRequests() *SystemUpdatePoolTooManyRequests {
	return &SystemUpdatePoolTooManyRequests{}
}

/*
SystemUpdatePoolTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SystemUpdatePoolTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this system update pool too many requests response has a 2xx status code
func (o *SystemUpdatePoolTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this system update pool too many requests response has a 3xx status code
func (o *SystemUpdatePoolTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this system update pool too many requests response has a 4xx status code
func (o *SystemUpdatePoolTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this system update pool too many requests response has a 5xx status code
func (o *SystemUpdatePoolTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this system update pool too many requests response a status code equal to that given
func (o *SystemUpdatePoolTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the system update pool too many requests response
func (o *SystemUpdatePoolTooManyRequests) Code() int {
	return 429
}

func (o *SystemUpdatePoolTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolTooManyRequests %s", 429, payload)
}

func (o *SystemUpdatePoolTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /system/pools/{ipID}][%d] systemUpdatePoolTooManyRequests %s", 429, payload)
}

func (o *SystemUpdatePoolTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SystemUpdatePoolTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
