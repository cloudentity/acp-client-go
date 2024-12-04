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

// RequestOTPChallengeReader is a Reader for the RequestOTPChallenge structure.
type RequestOTPChallengeReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RequestOTPChallengeReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRequestOTPChallengeNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRequestOTPChallengeUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRequestOTPChallengeNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewRequestOTPChallengePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewRequestOTPChallengeUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRequestOTPChallengeTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /admin/pools/{ipID}/users/{userID}/otp/request] requestOTPChallenge", response, response.Code())
	}
}

// NewRequestOTPChallengeNoContent creates a RequestOTPChallengeNoContent with default headers values
func NewRequestOTPChallengeNoContent() *RequestOTPChallengeNoContent {
	return &RequestOTPChallengeNoContent{}
}

/*
RequestOTPChallengeNoContent describes a response with status code 204, with default header values.

	Request accepted
*/
type RequestOTPChallengeNoContent struct {
}

// IsSuccess returns true when this request o t p challenge no content response has a 2xx status code
func (o *RequestOTPChallengeNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this request o t p challenge no content response has a 3xx status code
func (o *RequestOTPChallengeNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge no content response has a 4xx status code
func (o *RequestOTPChallengeNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this request o t p challenge no content response has a 5xx status code
func (o *RequestOTPChallengeNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge no content response a status code equal to that given
func (o *RequestOTPChallengeNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the request o t p challenge no content response
func (o *RequestOTPChallengeNoContent) Code() int {
	return 204
}

func (o *RequestOTPChallengeNoContent) Error() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeNoContent", 204)
}

func (o *RequestOTPChallengeNoContent) String() string {
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeNoContent", 204)
}

func (o *RequestOTPChallengeNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRequestOTPChallengeUnauthorized creates a RequestOTPChallengeUnauthorized with default headers values
func NewRequestOTPChallengeUnauthorized() *RequestOTPChallengeUnauthorized {
	return &RequestOTPChallengeUnauthorized{}
}

/*
RequestOTPChallengeUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RequestOTPChallengeUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this request o t p challenge unauthorized response has a 2xx status code
func (o *RequestOTPChallengeUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request o t p challenge unauthorized response has a 3xx status code
func (o *RequestOTPChallengeUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge unauthorized response has a 4xx status code
func (o *RequestOTPChallengeUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this request o t p challenge unauthorized response has a 5xx status code
func (o *RequestOTPChallengeUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge unauthorized response a status code equal to that given
func (o *RequestOTPChallengeUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the request o t p challenge unauthorized response
func (o *RequestOTPChallengeUnauthorized) Code() int {
	return 401
}

func (o *RequestOTPChallengeUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeUnauthorized %s", 401, payload)
}

func (o *RequestOTPChallengeUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeUnauthorized %s", 401, payload)
}

func (o *RequestOTPChallengeUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestOTPChallengeUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestOTPChallengeNotFound creates a RequestOTPChallengeNotFound with default headers values
func NewRequestOTPChallengeNotFound() *RequestOTPChallengeNotFound {
	return &RequestOTPChallengeNotFound{}
}

/*
RequestOTPChallengeNotFound describes a response with status code 404, with default header values.

Not found
*/
type RequestOTPChallengeNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this request o t p challenge not found response has a 2xx status code
func (o *RequestOTPChallengeNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request o t p challenge not found response has a 3xx status code
func (o *RequestOTPChallengeNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge not found response has a 4xx status code
func (o *RequestOTPChallengeNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this request o t p challenge not found response has a 5xx status code
func (o *RequestOTPChallengeNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge not found response a status code equal to that given
func (o *RequestOTPChallengeNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the request o t p challenge not found response
func (o *RequestOTPChallengeNotFound) Code() int {
	return 404
}

func (o *RequestOTPChallengeNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeNotFound %s", 404, payload)
}

func (o *RequestOTPChallengeNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeNotFound %s", 404, payload)
}

func (o *RequestOTPChallengeNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestOTPChallengeNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestOTPChallengePreconditionFailed creates a RequestOTPChallengePreconditionFailed with default headers values
func NewRequestOTPChallengePreconditionFailed() *RequestOTPChallengePreconditionFailed {
	return &RequestOTPChallengePreconditionFailed{}
}

/*
RequestOTPChallengePreconditionFailed describes a response with status code 412, with default header values.

Payload too large
*/
type RequestOTPChallengePreconditionFailed struct {
	Payload *models.Error
}

// IsSuccess returns true when this request o t p challenge precondition failed response has a 2xx status code
func (o *RequestOTPChallengePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request o t p challenge precondition failed response has a 3xx status code
func (o *RequestOTPChallengePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge precondition failed response has a 4xx status code
func (o *RequestOTPChallengePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this request o t p challenge precondition failed response has a 5xx status code
func (o *RequestOTPChallengePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge precondition failed response a status code equal to that given
func (o *RequestOTPChallengePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the request o t p challenge precondition failed response
func (o *RequestOTPChallengePreconditionFailed) Code() int {
	return 412
}

func (o *RequestOTPChallengePreconditionFailed) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengePreconditionFailed %s", 412, payload)
}

func (o *RequestOTPChallengePreconditionFailed) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengePreconditionFailed %s", 412, payload)
}

func (o *RequestOTPChallengePreconditionFailed) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestOTPChallengePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestOTPChallengeUnprocessableEntity creates a RequestOTPChallengeUnprocessableEntity with default headers values
func NewRequestOTPChallengeUnprocessableEntity() *RequestOTPChallengeUnprocessableEntity {
	return &RequestOTPChallengeUnprocessableEntity{}
}

/*
RequestOTPChallengeUnprocessableEntity describes a response with status code 422, with default header values.

Unprocessable entity
*/
type RequestOTPChallengeUnprocessableEntity struct {
	Payload *models.Error
}

// IsSuccess returns true when this request o t p challenge unprocessable entity response has a 2xx status code
func (o *RequestOTPChallengeUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request o t p challenge unprocessable entity response has a 3xx status code
func (o *RequestOTPChallengeUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge unprocessable entity response has a 4xx status code
func (o *RequestOTPChallengeUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this request o t p challenge unprocessable entity response has a 5xx status code
func (o *RequestOTPChallengeUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge unprocessable entity response a status code equal to that given
func (o *RequestOTPChallengeUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the request o t p challenge unprocessable entity response
func (o *RequestOTPChallengeUnprocessableEntity) Code() int {
	return 422
}

func (o *RequestOTPChallengeUnprocessableEntity) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeUnprocessableEntity %s", 422, payload)
}

func (o *RequestOTPChallengeUnprocessableEntity) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeUnprocessableEntity %s", 422, payload)
}

func (o *RequestOTPChallengeUnprocessableEntity) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestOTPChallengeUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRequestOTPChallengeTooManyRequests creates a RequestOTPChallengeTooManyRequests with default headers values
func NewRequestOTPChallengeTooManyRequests() *RequestOTPChallengeTooManyRequests {
	return &RequestOTPChallengeTooManyRequests{}
}

/*
RequestOTPChallengeTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RequestOTPChallengeTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this request o t p challenge too many requests response has a 2xx status code
func (o *RequestOTPChallengeTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this request o t p challenge too many requests response has a 3xx status code
func (o *RequestOTPChallengeTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this request o t p challenge too many requests response has a 4xx status code
func (o *RequestOTPChallengeTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this request o t p challenge too many requests response has a 5xx status code
func (o *RequestOTPChallengeTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this request o t p challenge too many requests response a status code equal to that given
func (o *RequestOTPChallengeTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the request o t p challenge too many requests response
func (o *RequestOTPChallengeTooManyRequests) Code() int {
	return 429
}

func (o *RequestOTPChallengeTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeTooManyRequests %s", 429, payload)
}

func (o *RequestOTPChallengeTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /admin/pools/{ipID}/users/{userID}/otp/request][%d] requestOTPChallengeTooManyRequests %s", 429, payload)
}

func (o *RequestOTPChallengeTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RequestOTPChallengeTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
