// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// RequestAddressVerificationReader is a Reader for the RequestAddressVerification structure.
type RequestAddressVerificationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RequestAddressVerificationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRequestAddressVerificationNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewRequestAddressVerificationBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewRequestAddressVerificationUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRequestAddressVerificationNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewRequestAddressVerificationConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewRequestAddressVerificationPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRequestAddressVerificationUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRequestAddressVerificationTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request] requestAddressVerification", response, response.Code())
	}
}

// NewRequestAddressVerificationNoContent creates a RequestAddressVerificationNoContent with default headers values
func NewRequestAddressVerificationNoContent() *RequestAddressVerificationNoContent {
	return &RequestAddressVerificationNoContent{}
}

/*
RequestAddressVerificationNoContent describes a response with status code 204, with default header values.

	Request accepted
*/
type RequestAddressVerificationNoContent struct {
}

// IsSuccess returns true when this request address verification no content response has a 2xx status code
func (o *RequestAddressVerificationNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this request address verification no content response has a 3xx status code
func (o *RequestAddressVerificationNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification no content response has a 4xx status code
func (o *RequestAddressVerificationNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this request address verification no content response has a 5xx status code
func (o *RequestAddressVerificationNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification no content response a status code equal to that given
func (o *RequestAddressVerificationNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the request address verification no content response
func (o *RequestAddressVerificationNoContent) Code() int {
	return 204
}

func (o *RequestAddressVerificationNoContent) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationNoContent", 204)
}

func (o *RequestAddressVerificationNoContent) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationNoContent", 204)
}

func (o *RequestAddressVerificationNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRequestAddressVerificationBadRequest creates a RequestAddressVerificationBadRequest with default headers values
func NewRequestAddressVerificationBadRequest() *RequestAddressVerificationBadRequest {
	return &RequestAddressVerificationBadRequest{}
}

/*
RequestAddressVerificationBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type RequestAddressVerificationBadRequest struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification bad request response has a 2xx status code
func (o *RequestAddressVerificationBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification bad request response has a 3xx status code
func (o *RequestAddressVerificationBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification bad request response has a 4xx status code
func (o *RequestAddressVerificationBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification bad request response has a 5xx status code
func (o *RequestAddressVerificationBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification bad request response a status code equal to that given
func (o *RequestAddressVerificationBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the request address verification bad request response
func (o *RequestAddressVerificationBadRequest) Code() int {
	return 400
}

func (o *RequestAddressVerificationBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationBadRequest %s", 400, payload)
}

func (o *RequestAddressVerificationBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationBadRequest %s", 400, payload)
}

func (o *RequestAddressVerificationBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationUnauthorized creates a RequestAddressVerificationUnauthorized with default headers values
func NewRequestAddressVerificationUnauthorized() *RequestAddressVerificationUnauthorized {
	return &RequestAddressVerificationUnauthorized{}
}

/*
RequestAddressVerificationUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RequestAddressVerificationUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification unauthorized response has a 2xx status code
func (o *RequestAddressVerificationUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification unauthorized response has a 3xx status code
func (o *RequestAddressVerificationUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification unauthorized response has a 4xx status code
func (o *RequestAddressVerificationUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification unauthorized response has a 5xx status code
func (o *RequestAddressVerificationUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification unauthorized response a status code equal to that given
func (o *RequestAddressVerificationUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the request address verification unauthorized response
func (o *RequestAddressVerificationUnauthorized) Code() int {
	return 401
}

func (o *RequestAddressVerificationUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationUnauthorized %s", 401, payload)
}

func (o *RequestAddressVerificationUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationUnauthorized %s", 401, payload)
}

func (o *RequestAddressVerificationUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationNotFound creates a RequestAddressVerificationNotFound with default headers values
func NewRequestAddressVerificationNotFound() *RequestAddressVerificationNotFound {
	return &RequestAddressVerificationNotFound{}
}

/*
RequestAddressVerificationNotFound describes a response with status code 404, with default header values.

Not found
*/
type RequestAddressVerificationNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification not found response has a 2xx status code
func (o *RequestAddressVerificationNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification not found response has a 3xx status code
func (o *RequestAddressVerificationNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification not found response has a 4xx status code
func (o *RequestAddressVerificationNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification not found response has a 5xx status code
func (o *RequestAddressVerificationNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification not found response a status code equal to that given
func (o *RequestAddressVerificationNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the request address verification not found response
func (o *RequestAddressVerificationNotFound) Code() int {
	return 404
}

func (o *RequestAddressVerificationNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationNotFound %s", 404, payload)
}

func (o *RequestAddressVerificationNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationNotFound %s", 404, payload)
}

func (o *RequestAddressVerificationNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationConflict creates a RequestAddressVerificationConflict with default headers values
func NewRequestAddressVerificationConflict() *RequestAddressVerificationConflict {
	return &RequestAddressVerificationConflict{}
}

/*
RequestAddressVerificationConflict describes a response with status code 409, with default header values.

Conflict
*/
type RequestAddressVerificationConflict struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification conflict response has a 2xx status code
func (o *RequestAddressVerificationConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification conflict response has a 3xx status code
func (o *RequestAddressVerificationConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification conflict response has a 4xx status code
func (o *RequestAddressVerificationConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification conflict response has a 5xx status code
func (o *RequestAddressVerificationConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification conflict response a status code equal to that given
func (o *RequestAddressVerificationConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the request address verification conflict response
func (o *RequestAddressVerificationConflict) Code() int {
	return 409
}

func (o *RequestAddressVerificationConflict) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationConflict %s", 409, payload)
}

func (o *RequestAddressVerificationConflict) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationConflict %s", 409, payload)
}

func (o *RequestAddressVerificationConflict) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationPreconditionFailed creates a RequestAddressVerificationPreconditionFailed with default headers values
func NewRequestAddressVerificationPreconditionFailed() *RequestAddressVerificationPreconditionFailed {
	return &RequestAddressVerificationPreconditionFailed{}
}

/*
RequestAddressVerificationPreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type RequestAddressVerificationPreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification precondition failed response has a 2xx status code
func (o *RequestAddressVerificationPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification precondition failed response has a 3xx status code
func (o *RequestAddressVerificationPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification precondition failed response has a 4xx status code
func (o *RequestAddressVerificationPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification precondition failed response has a 5xx status code
func (o *RequestAddressVerificationPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification precondition failed response a status code equal to that given
func (o *RequestAddressVerificationPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the request address verification precondition failed response
func (o *RequestAddressVerificationPreconditionFailed) Code() int {
	return 412
}

func (o *RequestAddressVerificationPreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationPreconditionFailed %s", 412, payload)
}

func (o *RequestAddressVerificationPreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationPreconditionFailed %s", 412, payload)
}

func (o *RequestAddressVerificationPreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationUnprocessableEntity creates a RequestAddressVerificationUnprocessableEntity with default headers values
func NewRequestAddressVerificationUnprocessableEntity() *RequestAddressVerificationUnprocessableEntity {
	return &RequestAddressVerificationUnprocessableEntity{}
}

/*
RequestAddressVerificationUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type RequestAddressVerificationUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification unprocessable entity response has a 2xx status code
func (o *RequestAddressVerificationUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification unprocessable entity response has a 3xx status code
func (o *RequestAddressVerificationUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification unprocessable entity response has a 4xx status code
func (o *RequestAddressVerificationUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification unprocessable entity response has a 5xx status code
func (o *RequestAddressVerificationUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification unprocessable entity response a status code equal to that given
func (o *RequestAddressVerificationUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the request address verification unprocessable entity response
func (o *RequestAddressVerificationUnprocessableEntity) Code() int {
	return 422
}

func (o *RequestAddressVerificationUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationUnprocessableEntity %s", 422, payload)
}

func (o *RequestAddressVerificationUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationUnprocessableEntity %s", 422, payload)
}

func (o *RequestAddressVerificationUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestAddressVerificationTooManyRequests creates a RequestAddressVerificationTooManyRequests with default headers values
func NewRequestAddressVerificationTooManyRequests() *RequestAddressVerificationTooManyRequests {
	return &RequestAddressVerificationTooManyRequests{}
}

/*
RequestAddressVerificationTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RequestAddressVerificationTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this request address verification too many requests response has a 2xx status code
func (o *RequestAddressVerificationTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request address verification too many requests response has a 3xx status code
func (o *RequestAddressVerificationTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request address verification too many requests response has a 4xx status code
func (o *RequestAddressVerificationTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this request address verification too many requests response has a 5xx status code
func (o *RequestAddressVerificationTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this request address verification too many requests response a status code equal to that given
func (o *RequestAddressVerificationTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the request address verification too many requests response
func (o *RequestAddressVerificationTooManyRequests) Code() int {
	return 429
}

func (o *RequestAddressVerificationTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationTooManyRequests %s", 429, payload)
}

func (o *RequestAddressVerificationTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/address/verification/request][%d] requestAddressVerificationTooManyRequests %s", 429, payload)
}

func (o *RequestAddressVerificationTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestAddressVerificationTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
