// Code generated by go-swagger; DO NOT EDIT.

package brute_force_limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// SetBruteForceLimitReader is a Reader for the SetBruteForceLimit structure.
type SetBruteForceLimitReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetBruteForceLimitReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewSetBruteForceLimitCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSetBruteForceLimitBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSetBruteForceLimitUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSetBruteForceLimitForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewSetBruteForceLimitNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewSetBruteForceLimitConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewSetBruteForceLimitUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewSetBruteForceLimitTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[PUT /bruteforce] setBruteForceLimit", response, response.Code())
	}
}

// NewSetBruteForceLimitCreated creates a SetBruteForceLimitCreated with default headers values
func NewSetBruteForceLimitCreated() *SetBruteForceLimitCreated {
	return &SetBruteForceLimitCreated{}
}

/*
SetBruteForceLimitCreated describes a response with status code 201, with default header values.

Brute force limit
*/
type SetBruteForceLimitCreated struct {

	/* The ETag HTTP header is an identifier for a specific version of a resource

	in:header

	     Format: etag
	*/
	Etag string

	Payload *models.BruteForceLimit
}

// IsSuccess returns true when this set brute force limit created response has a 2xx status code
func (o *SetBruteForceLimitCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set brute force limit created response has a 3xx status code
func (o *SetBruteForceLimitCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit created response has a 4xx status code
func (o *SetBruteForceLimitCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this set brute force limit created response has a 5xx status code
func (o *SetBruteForceLimitCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit created response a status code equal to that given
func (o *SetBruteForceLimitCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the set brute force limit created response
func (o *SetBruteForceLimitCreated) Code() int {
	return 201
}

func (o *SetBruteForceLimitCreated) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitCreated  %+v", 201, o.Payload)
}

func (o *SetBruteForceLimitCreated) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitCreated  %+v", 201, o.Payload)
}

func (o *SetBruteForceLimitCreated) GetPayload() *models.BruteForceLimit {
	return o.Payload
}

func (o *SetBruteForceLimitCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header etag
	hdrEtag := response.GetHeader("etag")

	if hdrEtag != "" {
		o.Etag = hdrEtag
	}

	o.Payload = new(models.BruteForceLimit)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitBadRequest creates a SetBruteForceLimitBadRequest with default headers values
func NewSetBruteForceLimitBadRequest() *SetBruteForceLimitBadRequest {
	return &SetBruteForceLimitBadRequest{}
}

/*
SetBruteForceLimitBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type SetBruteForceLimitBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit bad request response has a 2xx status code
func (o *SetBruteForceLimitBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit bad request response has a 3xx status code
func (o *SetBruteForceLimitBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit bad request response has a 4xx status code
func (o *SetBruteForceLimitBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit bad request response has a 5xx status code
func (o *SetBruteForceLimitBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit bad request response a status code equal to that given
func (o *SetBruteForceLimitBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the set brute force limit bad request response
func (o *SetBruteForceLimitBadRequest) Code() int {
	return 400
}

func (o *SetBruteForceLimitBadRequest) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitBadRequest  %+v", 400, o.Payload)
}

func (o *SetBruteForceLimitBadRequest) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitBadRequest  %+v", 400, o.Payload)
}

func (o *SetBruteForceLimitBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitUnauthorized creates a SetBruteForceLimitUnauthorized with default headers values
func NewSetBruteForceLimitUnauthorized() *SetBruteForceLimitUnauthorized {
	return &SetBruteForceLimitUnauthorized{}
}

/*
SetBruteForceLimitUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type SetBruteForceLimitUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit unauthorized response has a 2xx status code
func (o *SetBruteForceLimitUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit unauthorized response has a 3xx status code
func (o *SetBruteForceLimitUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit unauthorized response has a 4xx status code
func (o *SetBruteForceLimitUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit unauthorized response has a 5xx status code
func (o *SetBruteForceLimitUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit unauthorized response a status code equal to that given
func (o *SetBruteForceLimitUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the set brute force limit unauthorized response
func (o *SetBruteForceLimitUnauthorized) Code() int {
	return 401
}

func (o *SetBruteForceLimitUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitUnauthorized  %+v", 401, o.Payload)
}

func (o *SetBruteForceLimitUnauthorized) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitUnauthorized  %+v", 401, o.Payload)
}

func (o *SetBruteForceLimitUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitForbidden creates a SetBruteForceLimitForbidden with default headers values
func NewSetBruteForceLimitForbidden() *SetBruteForceLimitForbidden {
	return &SetBruteForceLimitForbidden{}
}

/*
SetBruteForceLimitForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type SetBruteForceLimitForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit forbidden response has a 2xx status code
func (o *SetBruteForceLimitForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit forbidden response has a 3xx status code
func (o *SetBruteForceLimitForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit forbidden response has a 4xx status code
func (o *SetBruteForceLimitForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit forbidden response has a 5xx status code
func (o *SetBruteForceLimitForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit forbidden response a status code equal to that given
func (o *SetBruteForceLimitForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the set brute force limit forbidden response
func (o *SetBruteForceLimitForbidden) Code() int {
	return 403
}

func (o *SetBruteForceLimitForbidden) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitForbidden  %+v", 403, o.Payload)
}

func (o *SetBruteForceLimitForbidden) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitForbidden  %+v", 403, o.Payload)
}

func (o *SetBruteForceLimitForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitNotFound creates a SetBruteForceLimitNotFound with default headers values
func NewSetBruteForceLimitNotFound() *SetBruteForceLimitNotFound {
	return &SetBruteForceLimitNotFound{}
}

/*
SetBruteForceLimitNotFound describes a response with status code 404, with default header values.

Not found
*/
type SetBruteForceLimitNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit not found response has a 2xx status code
func (o *SetBruteForceLimitNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit not found response has a 3xx status code
func (o *SetBruteForceLimitNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit not found response has a 4xx status code
func (o *SetBruteForceLimitNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit not found response has a 5xx status code
func (o *SetBruteForceLimitNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit not found response a status code equal to that given
func (o *SetBruteForceLimitNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the set brute force limit not found response
func (o *SetBruteForceLimitNotFound) Code() int {
	return 404
}

func (o *SetBruteForceLimitNotFound) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitNotFound  %+v", 404, o.Payload)
}

func (o *SetBruteForceLimitNotFound) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitNotFound  %+v", 404, o.Payload)
}

func (o *SetBruteForceLimitNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitConflict creates a SetBruteForceLimitConflict with default headers values
func NewSetBruteForceLimitConflict() *SetBruteForceLimitConflict {
	return &SetBruteForceLimitConflict{}
}

/*
SetBruteForceLimitConflict describes a response with status code 409, with default header values.

Conflict
*/
type SetBruteForceLimitConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit conflict response has a 2xx status code
func (o *SetBruteForceLimitConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit conflict response has a 3xx status code
func (o *SetBruteForceLimitConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit conflict response has a 4xx status code
func (o *SetBruteForceLimitConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit conflict response has a 5xx status code
func (o *SetBruteForceLimitConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit conflict response a status code equal to that given
func (o *SetBruteForceLimitConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the set brute force limit conflict response
func (o *SetBruteForceLimitConflict) Code() int {
	return 409
}

func (o *SetBruteForceLimitConflict) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitConflict  %+v", 409, o.Payload)
}

func (o *SetBruteForceLimitConflict) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitConflict  %+v", 409, o.Payload)
}

func (o *SetBruteForceLimitConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitUnprocessableEntity creates a SetBruteForceLimitUnprocessableEntity with default headers values
func NewSetBruteForceLimitUnprocessableEntity() *SetBruteForceLimitUnprocessableEntity {
	return &SetBruteForceLimitUnprocessableEntity{}
}

/*
SetBruteForceLimitUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type SetBruteForceLimitUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit unprocessable entity response has a 2xx status code
func (o *SetBruteForceLimitUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit unprocessable entity response has a 3xx status code
func (o *SetBruteForceLimitUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit unprocessable entity response has a 4xx status code
func (o *SetBruteForceLimitUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit unprocessable entity response has a 5xx status code
func (o *SetBruteForceLimitUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit unprocessable entity response a status code equal to that given
func (o *SetBruteForceLimitUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the set brute force limit unprocessable entity response
func (o *SetBruteForceLimitUnprocessableEntity) Code() int {
	return 422
}

func (o *SetBruteForceLimitUnprocessableEntity) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetBruteForceLimitUnprocessableEntity) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *SetBruteForceLimitUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSetBruteForceLimitTooManyRequests creates a SetBruteForceLimitTooManyRequests with default headers values
func NewSetBruteForceLimitTooManyRequests() *SetBruteForceLimitTooManyRequests {
	return &SetBruteForceLimitTooManyRequests{}
}

/*
SetBruteForceLimitTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type SetBruteForceLimitTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this set brute force limit too many requests response has a 2xx status code
func (o *SetBruteForceLimitTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this set brute force limit too many requests response has a 3xx status code
func (o *SetBruteForceLimitTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set brute force limit too many requests response has a 4xx status code
func (o *SetBruteForceLimitTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this set brute force limit too many requests response has a 5xx status code
func (o *SetBruteForceLimitTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this set brute force limit too many requests response a status code equal to that given
func (o *SetBruteForceLimitTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the set brute force limit too many requests response
func (o *SetBruteForceLimitTooManyRequests) Code() int {
	return 429
}

func (o *SetBruteForceLimitTooManyRequests) Error() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetBruteForceLimitTooManyRequests) String() string {
	return fmt.Sprintf("[PUT /bruteforce][%d] setBruteForceLimitTooManyRequests  %+v", 429, o.Payload)
}

func (o *SetBruteForceLimitTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *SetBruteForceLimitTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
